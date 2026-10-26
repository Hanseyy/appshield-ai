import requests
import re
from urllib.parse import urlparse
import socket
import ipaddress

def is_internal_ip(ip: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_multicast
    except ValueError:
        return False

def check_url_security(url: str):
    safe_indicators = []
    suspicious_indicators = []
    high_risk_indicators = []
    
    risk_score = 0
    
    parsed = urlparse(url)
    domain = parsed.netloc.split(':')[0]
    protocol = parsed.scheme
    
    # 1. Protocol check
    if protocol not in ['http', 'https']:
        return {"error": f"Unsupported protocol: {protocol}"}
    
    if protocol == 'http':
        suspicious_indicators.append({
            "status": "⚠", "severity": "Suspicious", "check_name": "Insecure Protocol", "explanation": "The URL uses HTTP instead of HTTPS, meaning traffic is unencrypted."
        })
        risk_score += 20
        https_status = False
    else:
        https_status = True
        safe_indicators.append({
            "status": "✓", "severity": "Safe", "check_name": "HTTPS Enabled", "explanation": "The connection is encrypted using HTTPS."
        })
        
    # 2. SSRF prevention / IP check
    try:
        ip = socket.gethostbyname(domain)
        if is_internal_ip(ip):
            return {"error": "Internal IP addresses are not allowed"}
    except socket.gaierror:
        pass 
        
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain):
        high_risk_indicators.append({
            "status": "✗", "severity": "High Risk", "check_name": "IP Address Hostname", "explanation": "An IP address is used instead of a domain name, common in phishing."
        })
        risk_score += 40
    else:
        safe_indicators.append({
            "status": "✓", "severity": "Safe", "check_name": "Domain Format", "explanation": "The URL uses a standard domain name format."
        })

    # 3. URL shorteners
    shortener_domains = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd']
    if any(d in domain for d in shortener_domains):
        suspicious_indicators.append({
            "status": "⚠", "severity": "Suspicious", "check_name": "URL Shortener", "explanation": "A URL shortening service is used, which masks the true destination."
        })
        risk_score += 15
        
    # 4. Long URLs
    if len(url) > 75:
        suspicious_indicators.append({
            "status": "⚠", "severity": "Suspicious", "check_name": "Unusual Length", "explanation": "The URL is unusually long, which can be used to hide suspicious parameters."
        })
        risk_score += 5
    else:
        safe_indicators.append({
            "status": "✓", "severity": "Safe", "check_name": "Normal URL Length", "explanation": "The URL length is within normal bounds."
        })
        
    # 5. Excessive subdomains
    if domain.count('.') > 3:
        suspicious_indicators.append({
            "status": "⚠", "severity": "Suspicious", "check_name": "Multiple Subdomains", "explanation": "The URL contains multiple nested subdomains, often used in phishing."
        })
        risk_score += 15

    # 6. Suspicious keywords in path/domain
    keywords = ['login', 'verify', 'update', 'secure', 'account', 'banking', 'wallet', 'password']
    url_lower = url.lower()
    found_keywords = [kw for kw in keywords if kw in parsed.path or kw in domain]
    if found_keywords:
        high_risk_indicators.append({
            "status": "✗", "severity": "High Risk", "check_name": "Suspicious Keywords", "explanation": f"The URL contains sensitive keywords ({', '.join(found_keywords)}) often targeted by phishing."
        })
        risk_score += 25
        
    # 7. Requesting the URL
    final_url = url
    redirects = 0
    try:
        session = requests.Session()
        session.max_redirects = 5
        response = session.head(url, allow_redirects=True, timeout=5)
        final_url = response.url
        redirects = len(response.history)
        
        if redirects > 2:
            suspicious_indicators.append({
                "status": "⚠", "severity": "Suspicious", "check_name": "Multiple Redirects", "explanation": f"High number of redirects ({redirects}) detected."
            })
            risk_score += 15
        else:
            safe_indicators.append({
                "status": "✓", "severity": "Safe", "check_name": "Redirect Chain", "explanation": "No excessive redirects detected."
            })
            
        final_domain = urlparse(final_url).netloc.split(':')[0]
        if final_domain != domain:
            suspicious_indicators.append({
                "status": "⚠", "severity": "Suspicious", "check_name": "Domain Redirect", "explanation": f"Redirects to a different domain: {final_domain}"
            })
            risk_score += 20
            
    except requests.TooManyRedirects:
        high_risk_indicators.append({
            "status": "✗", "severity": "High Risk", "check_name": "Redirect Loop", "explanation": "Too many redirects encountered, possible evasion technique."
        })
        risk_score += 50
    except requests.RequestException as e:
        suspicious_indicators.append({
            "status": "⚠", "severity": "Suspicious", "check_name": "Fetch Failed", "explanation": f"Failed to securely evaluate URL endpoint: {str(e)}"
        })
        risk_score += 10
        
    risk_score = min(risk_score, 100)
    
    if risk_score > 60:
        verdict = "High Risk"
    elif risk_score > 25:
        verdict = "Suspicious"
    else:
        verdict = "Safe"
        
    explanation = "The URL appears legitimate based on initial checks."
    if risk_score > 25:
        explanation = f"Flagged due to potentially risky indicators. Exercise caution."
        
    recommendations = []
    if https_status == False:
        recommendations.append("The URL uses HTTP instead of HTTPS. Do not enter credentials or sensitive information.")
    if found_keywords:
        recommendations.append("The URL contains characteristics commonly associated with obfuscation and phishing (sensitive keywords). Verify the domain before entering credentials.")
    if not recommendations:
        recommendations.append("No immediate threats detected, but always ensure the domain exactly matches the expected service.")

    return {
        "url": url,
        "final_url": final_url,
        "domain": domain,
        "protocol": protocol,
        "https_status": https_status,
        "redirects": redirects,
        "risk_score": risk_score,
        "risk_level": verdict,
        "safe_indicators": safe_indicators,
        "suspicious_indicators": suspicious_indicators,
        "high_risk_indicators": high_risk_indicators,
        "explanation": explanation,
        "recommendations": recommendations,
        "summary": {
            "safe": len(safe_indicators),
            "suspicious": len(suspicious_indicators),
            "high_risk": len(high_risk_indicators)
        }
    }
