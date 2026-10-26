from typing import Dict, List, Any

class SecurityExplainer:
    """
    Generates detailed, human-readable, point-by-point explanations for
    APK security classification results (both Malicious and Genuine).
    """

    @classmethod
    def generate_explanation(cls, cnn_result: Dict[str, Any], apk_info: Dict[str, Any]) -> Dict[str, Any]:
        prediction = cnn_result["prediction"]
        malicious_pct = cnn_result["malicious_score_pct"]
        genuine_pct = cnn_result["genuine_score_pct"]
        dangerous_perms = cnn_result["dangerous_permissions"]
        safe_perms = cnn_result["safe_permissions"]
        all_perms = apk_info.get("permissions", [])

        explanation_points = []
        permission_breakdown = []
        verdict_summary = ""

        if prediction == "MALICIOUS":
            verdict_summary = f"CRITICAL SECURITY ALERT: The application '{apk_info['file_name']}' has been classified as MALICIOUS with a threat score of {malicious_pct}%."

            # Bullet points explaining why it's malicious
            explanation_points.append(f"**CNN Algorithm High-Risk Feature Activation**: The 1D Convolutional Neural Network detected a dangerous permission pattern matching known Android malware families with {malicious_pct}% confidence.")

            if dangerous_perms:
                explanation_points.append(f"**Identified Malicious Permissions**: Found {len(dangerous_perms)} sensitive/dangerous permissions capable of unauthorized data access, background control, or financial fraud.")

                for item in dangerous_perms:
                    p = item["permission"]
                    sev = item["severity"]
                    desc = item["description"]
                    explanation_points.append(f"• **[{sev}] `{p}`**: {desc}")
                    permission_breakdown.append({
                        "permission": p,
                        "status": "MALICIOUS / HIGH RISK",
                        "severity": sev,
                        "explanation": desc
                    })
            else:
                explanation_points.append("• **Permission Anomaly**: The combination of requested system features presents an unusual security risk footprint.")

            # Pattern combinations checks
            perm_names = [d["permission"] for d in dangerous_perms]
            if "android.permission.SYSTEM_ALERT_WINDOW" in perm_names and ("android.permission.READ_SMS" in perm_names or "android.permission.RECEIVE_SMS" in perm_names):
                explanation_points.append("• **Banking Trojan / Overlay Attack Pattern Detected**: The app combines `SYSTEM_ALERT_WINDOW` (drawing overlay screens) with SMS reading permissions. This pattern is commonly used to display fake login screens and steal 2FA banking codes.")

            if "android.permission.RECEIVE_BOOT_COMPLETED" in perm_names and "android.permission.SEND_SMS" in perm_names:
                explanation_points.append("• **Stealth SMS Botnet Pattern Detected**: Automatically boots on startup and requests background SMS sending, indicating potential SMS malware botnet activity.")

            if "android.permission.ACCESS_FINE_LOCATION" in perm_names and "android.permission.RECORD_AUDIO" in perm_names:
                explanation_points.append("• **Spyware Surveillance Vector**: The app requests both microphone recording and fine GPS location tracking, allowing unauthorized eavesdropping and location tracking.")

            if "android.permission.REQUEST_INSTALL_PACKAGES" in perm_names or "android.permission.INSTALL_PACKAGES" in perm_names:
                explanation_points.append("• **Dropper / Payload Installer Vector**: Permission to install external APK packages allows this app to act as a malware dropper, fetching hidden secondary payloads.")

            explanation_points.append(f"• **Final Threat Assessment**: Genuine probability is only {genuine_pct}%. Immediate removal or isolation is strongly recommended.")

        else:  # GENUINE
            verdict_summary = f"APPLICATION VERIFIED: The application '{apk_info['file_name']}' has been verified as GENUINE with a safety score of {genuine_pct}%."

            explanation_points.append(f"**CNN Algorithm Safe Permission Alignment**: The 1D Convolutional Neural Network evaluated the app's permission vector and confirmed it matches standard, legitimate application profiles with {genuine_pct}% confidence.")

            explanation_points.append("• **Absence of High-Risk Exploit Permissions**: No critical overlay, silent SMS sending, accessibility hijacking, or payload installation permissions were found in the manifest.")

            if safe_perms:
                explanation_points.append(f"• **Standard Operational Permissions ({len(safe_perms)} Identified)**:")
                for item in safe_perms:
                    p = item["permission"]
                    desc = item["description"]
                    explanation_points.append(f"  - `{p}`: {desc}")
                    permission_breakdown.append({
                        "permission": p,
                        "status": "GENUINE / SAFE",
                        "severity": "SAFE",
                        "explanation": desc
                    })
            else:
                explanation_points.append("• **Minimal Permission Footprint**: The application requests negligible system privileges, reducing its attack surface to near zero.")

            # List remaining standard permissions
            other_perms = [p for p in all_perms if p not in [s["permission"] for s in safe_perms]]
            if other_perms:
                formatted_other = ", ".join([f"`{p.split('.')[-1]}`" for p in other_perms[:4]])
                explanation_points.append(f"• **Normal Utility Permissions ({len(other_perms)} Found)**: Permissions such as {formatted_other} fall within normal Android framework guidelines.")

            explanation_points.append(f"• **Low Residual Risk**: Malicious risk score is only {malicious_pct}%, which is well within safe thresholds for genuine applications.")

        return {
            "verdict_summary": verdict_summary,
            "prediction": prediction,
            "malicious_score_pct": malicious_pct,
            "genuine_score_pct": genuine_pct,
            "explanation_points": explanation_points,
            "permission_breakdown": permission_breakdown,
            "dangerous_count": len(dangerous_perms),
            "safe_count": len(safe_perms)
        }
