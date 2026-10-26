def analyze_permissions(permissions_list):
    # Categories
    POTENTIALLY_SUSPICIOUS = "Potentially Suspicious"
    SENSITIVE = "Sensitive / Requires Review"
    EXPECTED = "Expected / Legitimate"
    LOW_RISK = "Low Risk"

    # Known permissions mapping
    KNOWN_PERMISSIONS = {
        "android.permission.INTERNET": {
            "category": EXPECTED,
            "risk_level": "Low",
            "description": "Allows network communication.",
            "reason": "Commonly required by applications that communicate with online services."
        },
        "android.permission.ACCESS_NETWORK_STATE": {
            "category": LOW_RISK,
            "risk_level": "Low",
            "description": "Allows app to access information about networks.",
            "reason": "Standard for checking connectivity before downloading data."
        },
        "android.permission.ACCESS_WIFI_STATE": {
            "category": LOW_RISK,
            "risk_level": "Low",
            "description": "Allows app to access information about Wi-Fi networks.",
            "reason": "Standard for checking network status."
        },
        "android.permission.ACCESS_FINE_LOCATION": {
            "category": SENSITIVE,
            "risk_level": "Medium",
            "description": "Allows precise location access.",
            "reason": "Sensitive permission that may be legitimate for maps/navigation applications."
        },
        "android.permission.ACCESS_COARSE_LOCATION": {
            "category": SENSITIVE,
            "risk_level": "Medium",
            "description": "Allows approximate location access.",
            "reason": "Used for location-aware content, requires user trust."
        },
        "android.permission.CAMERA": {
            "category": SENSITIVE,
            "risk_level": "Medium",
            "description": "Allows camera access.",
            "reason": "May be legitimate for applications that provide camera/video functionality."
        },
        "android.permission.RECORD_AUDIO": {
            "category": SENSITIVE,
            "risk_level": "Medium",
            "description": "Allows recording audio.",
            "reason": "Highly sensitive if the app has no obvious voice or recording feature."
        },
        "android.permission.READ_CONTACTS": {
            "category": SENSITIVE,
            "risk_level": "Medium",
            "description": "Allows reading the user's contacts data.",
            "reason": "Can be exploited for data harvesting if the app doesn't inherently need it."
        },
        "android.permission.WRITE_CONTACTS": {
            "category": SENSITIVE,
            "risk_level": "Medium",
            "description": "Allows writing to the user's contacts data.",
            "reason": "Unusual for standard apps, typically for address book replacements."
        },
        "android.permission.READ_SMS": {
            "category": POTENTIALLY_SUSPICIOUS,
            "risk_level": "High",
            "description": "Allows the application to read SMS messages.",
            "reason": "Requires scrutiny if SMS functionality is not expected. Often abused by spyware."
        },
        "android.permission.RECEIVE_SMS": {
            "category": POTENTIALLY_SUSPICIOUS,
            "risk_level": "High",
            "description": "Allows app to receive and process SMS messages.",
            "reason": "High risk for OTP interception and billing fraud."
        },
        "android.permission.SEND_SMS": {
            "category": POTENTIALLY_SUSPICIOUS,
            "risk_level": "High",
            "description": "Allows sending SMS messages.",
            "reason": "Can result in unexpected charges if abused."
        },
        "android.permission.READ_CALL_LOG": {
            "category": POTENTIALLY_SUSPICIOUS,
            "risk_level": "High",
            "description": "Allows reading the user's call log.",
            "reason": "Rarely needed by regular apps; potential privacy invasion."
        },
        "android.permission.WRITE_CALL_LOG": {
            "category": POTENTIALLY_SUSPICIOUS,
            "risk_level": "High",
            "description": "Allows modifying the user's call log.",
            "reason": "Almost exclusive to dialer replacements."
        },
        "android.permission.READ_PHONE_STATE": {
            "category": SENSITIVE,
            "risk_level": "Medium",
            "description": "Allows read access to phone state, including phone number.",
            "reason": "Often used for tracking (IMEI) or pausing media during calls."
        },
        "android.permission.READ_EXTERNAL_STORAGE": {
            "category": SENSITIVE,
            "risk_level": "Medium",
            "description": "Allows reading from external storage.",
            "reason": "Required for accessing user files, photos, or media."
        },
        "android.permission.WRITE_EXTERNAL_STORAGE": {
            "category": SENSITIVE,
            "risk_level": "Medium",
            "description": "Allows writing to external storage.",
            "reason": "Required for saving downloaded files or media."
        },
        "android.permission.REQUEST_INSTALL_PACKAGES": {
            "category": POTENTIALLY_SUSPICIOUS,
            "risk_level": "High",
            "description": "Allows the app to request package installations.",
            "reason": "Requires additional scrutiny because it can allow installation of secondary malicious packages."
        },
        "android.permission.SYSTEM_ALERT_WINDOW": {
            "category": POTENTIALLY_SUSPICIOUS,
            "risk_level": "High",
            "description": "Allows an app to create windows shown on top of all other apps.",
            "reason": "Requires additional scrutiny because it allows overlay behavior, often used in banking trojans."
        },
        "android.permission.PACKAGE_USAGE_STATS": {
            "category": SENSITIVE,
            "risk_level": "Medium",
            "description": "Allows an app to collect component usage statistics.",
            "reason": "Used to monitor user activity across the device."
        },
        "android.permission.RECEIVE_BOOT_COMPLETED": {
            "category": SENSITIVE,
            "risk_level": "Medium",
            "description": "Allows an app to start automatically when the system finishes booting.",
            "reason": "Can be used to maintain persistence by malware."
        },
        "android.permission.VIBRATE": {
            "category": LOW_RISK,
            "risk_level": "Low",
            "description": "Allows access to the vibrator.",
            "reason": "Standard utility feature."
        }
    }

    categorized = {
        POTENTIALLY_SUSPICIOUS: [],
        SENSITIVE: [],
        EXPECTED: [],
        LOW_RISK: []
    }

    findings = []
    risk_score = 0

    for perm in permissions_list:
        p_name = perm
        if p_name.startswith("android.permission."):
            short_name = p_name.replace("android.permission.", "")
        else:
            short_name = p_name

        if perm in KNOWN_PERMISSIONS:
            info = KNOWN_PERMISSIONS[perm]
            cat = info["category"]
            finding = {
                "permission": short_name,
                "full_name": perm,
                "risk_level": info["risk_level"],
                "category": cat,
                "description": info["description"],
                "reason": info["reason"]
            }
        else:
            # Fallback for unknown permissions
            cat = EXPECTED
            finding = {
                "permission": short_name,
                "full_name": perm,
                "risk_level": "Low",
                "category": cat,
                "description": "Custom or standard Android permission.",
                "reason": "Behavior specific to the app's standard functionality."
            }
        
        categorized[cat].append(finding)
        findings.append(finding)

        # Increment risk score
        if finding["category"] == POTENTIALLY_SUSPICIOUS:
            risk_score += 15
        elif finding["category"] == SENSITIVE:
            risk_score += 5
        else:
            risk_score += 0

    # Cap permission risk score to 100
    risk_score = min(risk_score, 100)

    # Generate recommendations
    recommendations = []
    if categorized[POTENTIALLY_SUSPICIOUS]:
        recommendations.append("Multiple sensitive permissions are requested. Review whether they are necessary for the application's stated purpose.")
        if any("SMS" in f["permission"] for f in categorized[POTENTIALLY_SUSPICIOUS]):
            recommendations.append("Review SMS access because the application requests access to read/write SMS messages.")
        if any(f["permission"] in ["SYSTEM_ALERT_WINDOW", "REQUEST_INSTALL_PACKAGES"] for f in categorized[POTENTIALLY_SUSPICIOUS]):
            recommendations.append("This application requests advanced system manipulation privileges (e.g. overlays or package installation). Exercise extreme caution.")
    if categorized[SENSITIVE]:
        if any(f["permission"] in ["ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION"] for f in categorized[SENSITIVE]):
            recommendations.append("Location access may be legitimate if the application's functionality requires location services.")
    
    if not recommendations:
        recommendations.append("No highly suspicious permissions detected, but ensure the application comes from a trusted source.")

    return {
        "categorized": categorized,
        "findings": findings,
        "permission_risk_score": risk_score,
        "recommendations": recommendations,
        "summary": {
            "total": len(permissions_list),
            "potentially_suspicious": len(categorized[POTENTIALLY_SUSPICIOUS]),
            "sensitive": len(categorized[SENSITIVE]),
            "expected": len(categorized[EXPECTED]),
            "low_risk": len(categorized[LOW_RISK])
        }
    }
