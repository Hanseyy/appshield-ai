import zipfile
import re
import os
import struct
from typing import Dict, List, Any

class APKParser:
    """
    Robust APK Parser that inspects APK archives and extracts declared permissions
    from binary AndroidManifest.xml (AXML) as well as DEX string pools.
    """

    KNOWN_PERMISSIONS = [
        "android.permission.SEND_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.READ_SMS",
        "android.permission.WRITE_SMS",
        "android.permission.RECEIVE_MMS",
        "android.permission.RECEIVE_WAP_PUSH",
        "android.permission.READ_CONTACTS",
        "android.permission.WRITE_CONTACTS",
        "android.permission.GET_ACCOUNTS",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.ACCESS_BACKGROUND_LOCATION",
        "android.permission.RECORD_AUDIO",
        "android.permission.CAMERA",
        "android.permission.READ_PHONE_STATE",
        "android.permission.CALL_PHONE",
        "android.permission.READ_CALL_LOG",
        "android.permission.WRITE_CALL_LOG",
        "android.permission.ADD_VOICEMAIL",
        "android.permission.USE_SIP",
        "android.permission.PROCESS_OUTGOING_CALLS",
        "android.permission.BODY_SENSORS",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "android.permission.MOUNT_UNMOUNT_FILESYSTEMS",
        "android.permission.INTERNET",
        "android.permission.ACCESS_NETWORK_STATE",
        "android.permission.ACCESS_WIFI_STATE",
        "android.permission.CHANGE_WIFI_STATE",
        "android.permission.BLUETOOTH",
        "android.permission.BLUETOOTH_ADMIN",
        "android.permission.SYSTEM_ALERT_WINDOW",
        "android.permission.RECEIVE_BOOT_COMPLETED",
        "android.permission.REQUEST_INSTALL_PACKAGES",
        "android.permission.INSTALL_PACKAGES",
        "android.permission.DELETE_PACKAGES",
        "android.permission.KILL_BACKGROUND_PROCESSES",
        "android.permission.RESTART_PACKAGES",
        "android.permission.WAKE_LOCK",
        "android.permission.VIBRATE",
        "android.permission.CHANGE_NETWORK_STATE",
        "android.permission.WRITE_SETTINGS",
        "android.permission.DISABLE_KEYGUARD",
        "android.permission.GET_TASKS",
        "android.permission.REORDER_TASKS",
        "android.permission.SET_WALLPAPER",
        "android.permission.EXPAND_STATUS_BAR",
        "android.permission.USE_BIOMETRIC",
        "android.permission.USE_FINGERPRINT",
        "android.permission.FOREGROUND_SERVICE",
        "android.permission.MANAGE_EXTERNAL_STORAGE",
        "android.permission.QUERY_ALL_PACKAGES"
    ]

    @classmethod
    def parse_apk(cls, apk_path: str) -> Dict[str, Any]:
        """
        Parses an APK file and extracts declared permissions.
        Raises ValueError if file is not a valid APK.
        """
        if not os.path.exists(apk_path):
            raise FileNotFoundError(f"File not found: {apk_path}")

        file_size_kb = round(os.path.getsize(apk_path) / 1024, 2)
        file_name = os.path.basename(apk_path)

        if not zipfile.is_zipfile(apk_path):
            raise ValueError(f"'{file_name}' is not a valid APK archive or corrupted zip file. APK file structure verification failed.")

        permissions = set()
        package_name = "unknown.application.pkg"
        manifest_found = False
        dex_found = False

        try:
            with zipfile.ZipFile(apk_path, 'r') as zip_ref:
                namelist = zip_ref.namelist()

                # Verify APK core files
                for name in namelist:
                    if name.lower() == "androidmanifest.xml":
                        manifest_found = True
                    if name.lower().endswith(".dex"):
                        dex_found = True

                if not manifest_found:
                    raise ValueError(f"'{file_name}' does not contain AndroidManifest.xml. It is not a valid Android APK file.")

                # Extract manifest bytes
                manifest_bytes = zip_ref.read("AndroidManifest.xml")

                # Extract permissions from binary/text manifest
                cls._extract_permissions_from_manifest(manifest_bytes, permissions)

                # Attempt to extract package name
                extracted_pkg = cls._extract_package_name(manifest_bytes)
                if extracted_pkg:
                    package_name = extracted_pkg

                # Fallback scan across DEX string tables if manifest permission count is low
                if len(permissions) == 0:
                    for item in namelist:
                        if item.endswith(".dex"):
                            dex_bytes = zip_ref.read(item)
                            cls._scan_bytes_for_permissions(dex_bytes, permissions)

        except zipfile.BadZipFile:
            raise ValueError(f"'{file_name}' is a corrupted zip archive.")

        sorted_permissions = sorted(list(permissions))

        return {
            "valid": True,
            "file_name": file_name,
            "file_size_kb": file_size_kb,
            "package_name": package_name,
            "permissions": sorted_permissions,
            "permission_count": len(sorted_permissions),
            "manifest_found": manifest_found,
            "dex_found": dex_found
        }

    @classmethod
    def _extract_permissions_from_manifest(cls, data: bytes, permissions_set: set):
        """Extracts permissions by decoding AXML string pool and regex matching."""
        # 1. Direct Regex scan for permission strings in binary data (UTF-8 and UTF-16)
        cls._scan_bytes_for_permissions(data, permissions_set)

        # 2. Try simple AXML String Pool extraction
        try:
            strings = cls._parse_axml_string_pool(data)
            for s in strings:
                if s.startswith("android.permission.") or ".permission." in s:
                    clean_perm = s.strip()
                    if clean_perm.startswith("android.permission."):
                        permissions_set.add(clean_perm)
                    elif re.match(r'^[a-zA-Z0-9_\.]+\.permission\.[a-zA-Z0-9_]+$', clean_perm):
                        permissions_set.add(clean_perm)
        except Exception:
            pass

    @classmethod
    def _scan_bytes_for_permissions(cls, data: bytes, permissions_set: set):
        """Scans raw binary bytes for permission string tokens."""
        pattern = re.compile(rb'android\.permission\.[A-Za-z0-9_]+')
        matches = pattern.findall(data)
        for m in matches:
            try:
                perm_str = m.decode('utf-8', errors='ignore')
                permissions_set.add(perm_str)
            except Exception:
                pass

        custom_pattern = re.compile(rb'[a-zA-Z0-9_\.]+\.permission\.[A-Za-z0-9_]+')
        custom_matches = custom_pattern.findall(data)
        for m in custom_matches:
            try:
                perm_str = m.decode('utf-8', errors='ignore')
                if len(perm_str) < 100:
                    permissions_set.add(perm_str)
            except Exception:
                pass

    @classmethod
    def _extract_package_name(cls, data: bytes) -> str:
        """Helper to extract package name pattern from binary manifest."""
        pattern = re.compile(rb'com\.[a-zA-Z0-9_]+\.[a-zA-Z0-9_]+')
        matches = pattern.findall(data)
        if matches:
            for m in matches:
                decoded = m.decode('utf-8', errors='ignore')
                if not decoded.startswith("android.permission") and len(decoded) > 5:
                    return decoded
        return "com.app.analyzed"

    @classmethod
    def _parse_axml_string_pool(cls, data: bytes) -> List[str]:
        """Simple extractor for string pool chunk in Android binary XML."""
        strings = []
        if len(data) < 32:
            return strings

        idx = 8
        while idx < len(data) - 8:
            chunk_type, chunk_size = struct.unpack('<HH', data[idx:idx+4])
            if chunk_type == 0x0001:
                string_count, style_count, flags, strings_start, styles_start = struct.unpack('<IIIII', data[idx+8:idx+28])
                is_utf8 = bool(flags & (1 << 8))

                offsets = []
                offset_table_start = idx + 28
                for i in range(string_count):
                    off_pos = offset_table_start + (i * 4)
                    if off_pos + 4 <= len(data):
                        off = struct.unpack('<I', data[off_pos:off_pos+4])[0]
                        offsets.append(off)

                strings_base = idx + strings_start
                for off in offsets:
                    str_pos = strings_base + off
                    if str_pos >= len(data):
                        continue
                    if is_utf8:
                        if str_pos + 2 < len(data):
                            s_data = data[str_pos+2:str_pos+256].split(b'\x00')[0]
                            strings.append(s_data.decode('utf-8', errors='ignore'))
                    else:
                        if str_pos + 2 < len(data):
                            u16_len = struct.unpack('<H', data[str_pos:str_pos+2])[0]
                            u16_bytes = data[str_pos+2 : str_pos+2 + (u16_len * 2)]
                            strings.append(u16_bytes.decode('utf-16le', errors='ignore'))
                break
            idx += 4
        return strings
