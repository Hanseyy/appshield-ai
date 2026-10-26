import zipfile
import os
from typing import List

class SampleAPKGenerator:
    """
    Utility class to programmatically generate valid synthetic APK test archives
    with encoded permission sets for immediate testing and verification.
    """

    @classmethod
    def create_apk(cls, output_path: str, package_name: str, permissions: List[str]):
        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        # Build binary string pool manifest content
        manifest_content = bytearray()
        manifest_content.extend(b"Android Binary Manifest Header\x00\x08\x00\x03")
        manifest_content.extend(f"Package:{package_name}\x00".encode('utf-8'))

        # Add string pool chunk header
        manifest_content.extend(b"\x01\x00\x1c\x00")
        for p in permissions:
            manifest_content.extend(f" {p} ".encode('utf-8'))
            manifest_content.extend(b"\x00")

        # Fake classes.dex header
        dex_content = bytearray(b"dex\n035\x00" + b"\x00" * 100)
        for p in permissions:
            dex_content.extend(f"L{p.replace('.', '/')};".encode('utf-8'))

        with zipfile.ZipFile(output_path, 'w', compression=zipfile.ZIP_DEFLATED) as zip_out:
            zip_out.writestr("AndroidManifest.xml", bytes(manifest_content))
            zip_out.writestr("classes.dex", bytes(dex_content))
            zip_out.writestr("META-INF/MANIFEST.MF", f"Manifest-Version: 1.0\r\nCreated-By: CNN-Malware-Detector\r\nPackage: {package_name}\r\n".encode('utf-8'))
            zip_out.writestr("res/values/strings.xml", b"<resources><string name=\"app_name\">Sample Test App</string></resources>")

    @classmethod
    def generate_all_samples(cls, samples_dir: str):
        os.makedirs(samples_dir, exist_ok=True)

        # 1. Banking Trojan Malware APK
        cls.create_apk(
            os.path.join(samples_dir, "banking_trojan_malware.apk"),
            "com.financial.banking.secure.trojan",
            [
                "android.permission.SEND_SMS",
                "android.permission.RECEIVE_SMS",
                "android.permission.READ_SMS",
                "android.permission.SYSTEM_ALERT_WINDOW",
                "android.permission.RECEIVE_BOOT_COMPLETED",
                "android.permission.READ_CONTACTS",
                "android.permission.REQUEST_INSTALL_PACKAGES",
                "android.permission.INTERNET"
            ]
        )

        # 2. Stealth Spyware Malware APK
        cls.create_apk(
            os.path.join(samples_dir, "stealth_spyware_malware.apk"),
            "com.system.service.spyware",
            [
                "android.permission.ACCESS_FINE_LOCATION",
                "android.permission.RECORD_AUDIO",
                "android.permission.CAMERA",
                "android.permission.READ_PHONE_STATE",
                "android.permission.READ_CALL_LOG",
                "android.permission.RECEIVE_BOOT_COMPLETED",
                "android.permission.INTERNET"
            ]
        )

        # 3. Clean Calculator Genuine APK
        cls.create_apk(
            os.path.join(samples_dir, "clean_calculator_genuine.apk"),
            "com.utility.simple.calculator",
            [
                "android.permission.VIBRATE",
                "android.permission.INTERNET"
            ]
        )

        # 4. Clean Photo Editor Genuine APK
        cls.create_apk(
            os.path.join(samples_dir, "clean_photo_editor_genuine.apk"),
            "com.creative.photo.editor.studio",
            [
                "android.permission.CAMERA",
                "android.permission.READ_EXTERNAL_STORAGE",
                "android.permission.WRITE_EXTERNAL_STORAGE",
                "android.permission.VIBRATE",
                "android.permission.INTERNET",
                "android.permission.ACCESS_NETWORK_STATE"
            ]
        )

if __name__ == "__main__":
    SampleAPKGenerator.generate_all_samples("samples")
    print("Sample APKs successfully generated in samples/")
