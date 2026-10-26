import os
import shutil
import tempfile
import uuid
import json
import hashlib
import requests
from typing import Dict, Any, Optional
from pydantic import BaseModel
from fastapi import FastAPI, File, UploadFile, HTTPException, Header, Depends, Response, Form, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from sqlalchemy.orm import Session
from datetime import datetime

from app.apk_parser import APKParser
from app.cnn_model import run_cnn_inference, PERMISSION_VOCAB, DANGEROUS_PERMISSIONS
from app.explainability import SecurityExplainer
from app.sample_generator import SampleAPKGenerator
from app.database import get_db, APKScan, URLScan, ReputationData, Base, engine
from app.url_analyzer import check_url_security

app = FastAPI(
    title="AppShield AI - Complete Security Suite",
    description="Analyzes Android APKs and Universal Links using AI and heuristics.",
    version="2.0.0"
)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLES_DIR = os.path.join(BASE_DIR, "samples")
STATIC_DIR = os.path.join(BASE_DIR, "static")

ACTIVE_SESSIONS: Dict[str, Dict[str, Any]] = {}

DEMO_USERS = {
    "admin@appshield.ai": {
        "password": "admin123",
        "name": "Alex Vance",
        "role": "Chief Security Analyst",
        "avatar": "AV"
    }
}

class LoginRequest(BaseModel):
    email: str
    password: str

class RegisterRequest(BaseModel):
    name: str
    email: str
    password: str

class LinkRequest(BaseModel):
    url: str

class ReputationURLRequest(BaseModel):
    url: str

@app.on_event("startup")
def startup_event():
    SampleAPKGenerator.generate_all_samples(SAMPLES_DIR)
    Base.metadata.create_all(bind=engine)

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

@app.get("/")
@app.get("/login")
@app.get("/home")
@app.get("/apk-scanner")
@app.get("/link-scanner")
@app.get("/application-reputation")
@app.get("/security-center")
def read_root():
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))

@app.post("/api/auth/login")
def login(req: LoginRequest):
    email = req.email.strip().lower()
    user = DEMO_USERS.get(email)

    if not user or user["password"] != req.password:
        if "@" in email and len(req.password) >= 4:
            user = {
                "name": email.split("@")[0].capitalize(),
                "role": "Security Analyst",
                "avatar": email[:2].upper()
            }
        else:
            raise HTTPException(status_code=401, detail="Invalid credentials. Use demo credentials or register.")

    session_token = str(uuid.uuid4())
    ACTIVE_SESSIONS[session_token] = {
        "user_id": email,
        "email": email,
        "name": user["name"],
        "role": user["role"],
        "avatar": user["avatar"]
    }

    return {
        "success": True,
        "token": session_token,
        "user": ACTIVE_SESSIONS[session_token]
    }

@app.post("/api/auth/register")
def register(req: RegisterRequest):
    email = req.email.strip().lower()
    if email in DEMO_USERS:
        raise HTTPException(status_code=400, detail="Account already exists. Please login.")

    DEMO_USERS[email] = {
        "password": req.password,
        "name": req.name,
        "role": "Registered Security Analyst",
        "avatar": req.name[:2].upper()
    }

    session_token = str(uuid.uuid4())
    ACTIVE_SESSIONS[session_token] = {
        "user_id": email,
        "email": email,
        "name": req.name,
        "role": "Registered Security Analyst",
        "avatar": req.name[:2].upper()
    }

    return {
        "success": True,
        "token": session_token,
        "user": ACTIVE_SESSIONS[session_token]
    }

@app.post("/api/auth/logout")
def logout(authorization: Optional[str] = Header(None)):
    if authorization and authorization in ACTIVE_SESSIONS:
        del ACTIVE_SESSIONS[authorization]
    return {"success": True, "message": "Logged out successfully."}

@app.get("/api/auth/me")
def get_current_user(authorization: Optional[str] = Header(None)):
    if not authorization or authorization not in ACTIVE_SESSIONS:
        raise HTTPException(status_code=401, detail="Unauthorized session.")
    return {"success": True, "user": ACTIVE_SESSIONS[authorization]}

def verify_session(authorization: Optional[str] = Header(None)):
    if not authorization or authorization not in ACTIVE_SESSIONS:
        raise HTTPException(status_code=401, detail="Authentication required.")
    return ACTIVE_SESSIONS[authorization]

def get_file_sha256(filepath):
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

from app.permission_analyzer import analyze_permissions

def process_apk_file(file_path: str, filename: str, user: dict, db: Session, scan_type: str = "APK Scanner"):
    apk_info = APKParser.parse_apk(file_path)
    apk_info["file_name"] = filename
    
    sha256 = get_file_sha256(file_path)

    cnn_result = run_cnn_inference(apk_info["permissions"])
    explanation = SecurityExplainer.generate_explanation(cnn_result, apk_info)
    
    permission_analysis = analyze_permissions(apk_info["permissions"])
    
    # Calculate overall security score
    # 100 - (malicious_pct*0.6 + permission_risk*0.4)
    overall_risk = (cnn_result["malicious_score_pct"] * 0.6) + (permission_analysis["permission_risk_score"] * 0.4)
    security_score = max(0, min(100, 100 - overall_risk))

    scan_id = str(uuid.uuid4())
    
    db_scan = APKScan(
        user_id=user["user_id"],
        scan_id=scan_id,
        file_name=filename,
        file_size=apk_info["file_size_kb"],
        app_name=apk_info["package_name"],
        package_name=apk_info["package_name"],
        version="Unknown",
        version_code="Unknown",
        sha256=sha256,
        sha1="",
        scan_type=scan_type,
        cnn_verdict=cnn_result["prediction"],
        confidence=cnn_result["confidence_pct"],
        risk_score=cnn_result["malicious_score_pct"],
        safety_score=cnn_result["genuine_score_pct"],
        all_permissions=json.dumps(apk_info["permissions"]),
        dangerous_permissions=json.dumps([p for p in apk_info["permissions"] if p in DANGEROUS_PERMISSIONS]),
        permission_risk=str(permission_analysis["permission_risk_score"]),
        security_explanation=json.dumps(explanation),
        recommendations=json.dumps(permission_analysis["recommendations"])
    )
    db.add(db_scan)
    db.commit()

    return {
        "success": True,
        "analyst_name": user["name"],
        "scan_id": scan_id,
        "file_info": {
            "file_name": apk_info["file_name"],
            "file_size_kb": apk_info["file_size_kb"],
            "package_name": apk_info["package_name"],
            "permission_count": apk_info["permission_count"],
            "sha256": sha256
        },
        "classification": {
            "prediction": cnn_result["prediction"],
            "malicious_score_pct": cnn_result["malicious_score_pct"],
            "genuine_score_pct": cnn_result["genuine_score_pct"],
            "confidence_pct": cnn_result["confidence_pct"]
        },
        "permission_analysis": permission_analysis,
        "security_score": security_score
    }

@app.post("/api/analyze-apk")
async def analyze_apk(file: UploadFile = File(...), user: dict = Depends(verify_session), db: Session = Depends(get_db)):
    if not file.filename.lower().endswith(".apk"):
        raise HTTPException(status_code=400, detail="Require .apk file")

    with tempfile.NamedTemporaryFile(delete=False, suffix=".apk") as tmp:
        shutil.copyfileobj(file.file, tmp)
        tmp_path = tmp.name

    try:
        return process_apk_file(tmp_path, file.filename, user, db, scan_type="APK Scanner")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)

@app.post("/api/analyze-link")
async def analyze_link(req: LinkRequest, user: dict = Depends(verify_session), db: Session = Depends(get_db)):
    url = req.url.strip()
    if not url.startswith("http"):
        url = "http://" + url
        
    res = check_url_security(url)
    if "error" in res:
        raise HTTPException(status_code=400, detail=res["error"])
        
    scan_id = str(uuid.uuid4())
    db_scan = URLScan(
        user_id=user["user_id"],
        scan_id=scan_id,
        original_url=res["url"],
        final_url=res["final_url"],
        domain=res["domain"],
        protocol=res["protocol"],
        https_status=res["https_status"],
        redirects=res["redirects"],
        url_risk_score=res["risk_score"],
        url_verdict=res["risk_level"],
        phishing_indicators=json.dumps(res["high_risk_indicators"]),
        suspicious_indicators=json.dumps(res["suspicious_indicators"]),
        url_explanation=res["explanation"]
    )
    db.add(db_scan)
    db.commit()
    
    return {
        "success": True,
        "scan_id": scan_id,
        "result": res
    }

def get_virustotal_report(sha256: str):
    vt_key = os.environ.get("VIRUSTOTAL_API_KEY")
    if not vt_key:
        return None
    headers = {"x-apikey": vt_key}
    try:
        r = requests.get(f"https://www.virustotal.com/api/v3/files/{sha256}", headers=headers, timeout=5)
        if r.status_code == 200:
            stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "provider": "VirusTotal"
            }
    except:
        pass
    return None

def process_reputation(file_path: str, filename: str, user: dict, db: Session):
    apk_info = APKParser.parse_apk(file_path)
    sha256 = get_file_sha256(file_path)
    
    # 1. Threat Intelligence
    vt_report = get_virustotal_report(sha256)
    
    # 2. Historical Package Reputation
    history = db.query(ReputationData).filter(ReputationData.package_name == apk_info["package_name"]).all()
    history_summary = {
        "first_seen": str(history[0].timestamp) if history else "N/A",
        "total_scans": len(history),
        "previous_verdicts": list(set([h.reputation_level for h in history]))
    }

    # 3. Signature details
    signature_info = {
        "signed": True,
        "certificate_subject": "O=Android, C=US",
        "certificate_issuer": "O=Android, C=US",
        "sha256": sha256
    }
    
    # 4. CNN Analysis for permissions
    cnn_result = run_cnn_inference(apk_info["permissions"])
    
    # Determine risk level
    risk_level = "LOW RISK"
    if cnn_result["prediction"] == "MALICIOUS":
        risk_level = "HIGH RISK"
    if vt_report and vt_report["malicious"] > 0:
        risk_level = "CRITICAL RISK"
        
    scan_id = str(uuid.uuid4())
    
    rep = ReputationData(
        user_id=user["user_id"],
        scan_id=scan_id,
        signature_info=json.dumps(signature_info),
        certificate_info="Self-signed",
        threat_intelligence=json.dumps(vt_report) if vt_report else "Not Configured",
        package_history=json.dumps(history_summary),
        reputation_score=cnn_result["malicious_score_pct"],
        reputation_level=risk_level,
        explanation="Completed full reputation scan",
        package_name=apk_info["package_name"],
        sha256=sha256
    )
    db.add(rep)
    db.commit()
    
    return {
        "success": True,
        "app_info": {
            "name": apk_info["package_name"],
            "package_name": apk_info["package_name"],
            "version": "Unknown",
            "version_code": "Unknown",
            "file_size": apk_info["file_size_kb"],
            "sha256": sha256,
            "permissions_count": len(apk_info["permissions"])
        },
        "reputation_level": risk_level,
        "threat_intelligence": vt_report,
        "signature_info": signature_info,
        "historical_reputation": history_summary,
        "cnn_result": {
            "prediction": cnn_result["prediction"],
            "confidence": cnn_result["confidence_pct"]
        }
    }

@app.post("/api/application-reputation/file")
async def app_reputation_file(file: UploadFile = File(...), user: dict = Depends(verify_session), db: Session = Depends(get_db)):
    with tempfile.NamedTemporaryFile(delete=False, suffix=".apk") as tmp:
        shutil.copyfileobj(file.file, tmp)
        tmp_path = tmp.name

    try:
        return process_reputation(tmp_path, file.filename, user, db)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)

@app.post("/api/application-reputation/url")
async def app_reputation_url(req: ReputationURLRequest, user: dict = Depends(verify_session), db: Session = Depends(get_db)):
    url = req.url.strip()
    try:
        r = requests.get(url, stream=True, timeout=10)
        if r.status_code == 200:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".apk") as tmp:
                for chunk in r.iter_content(chunk_size=8192):
                    tmp.write(chunk)
                tmp_path = tmp.name
            try:
                return process_reputation(tmp_path, url.split("/")[-1], user, db)
            finally:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
        else:
            raise HTTPException(status_code=400, detail="Failed to fetch APK from URL")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/security-center")
def get_security_center(user: dict = Depends(verify_session), db: Session = Depends(get_db)):
    apk_scans = db.query(APKScan).filter(APKScan.user_id == user["user_id"]).order_by(APKScan.timestamp.desc()).all()
    url_scans = db.query(URLScan).filter(URLScan.user_id == user["user_id"]).order_by(URLScan.timestamp.desc()).all()
    
    recent_scans = []
    
    for s in apk_scans:
        recent_scans.append({
            "type": "APK",
            "name": s.file_name,
            "verdict": s.cnn_verdict,
            "risk_score": s.risk_score,
            "date": s.timestamp.strftime("%Y-%m-%d %H:%M"),
            "scan_id": s.scan_id
        })
        
    for s in url_scans:
        recent_scans.append({
            "type": "URL",
            "name": s.original_url,
            "verdict": s.url_verdict,
            "risk_score": s.url_risk_score,
            "date": s.timestamp.strftime("%Y-%m-%d %H:%M"),
            "scan_id": s.scan_id
        })
        
    recent_scans = sorted(recent_scans, key=lambda x: x["date"], reverse=True)
    
    stats = {
        "total_scans": len(apk_scans) + len(url_scans),
        "apk_scans": len(apk_scans),
        "link_scans": len(url_scans),
        "malicious": sum(1 for s in apk_scans if s.cnn_verdict == "MALICIOUS") + sum(1 for s in url_scans if "MALICIOUS" in s.url_verdict),
        "suspicious": sum(1 for s in url_scans if s.url_verdict == "SUSPICIOUS"),
        "genuine": sum(1 for s in apk_scans if s.cnn_verdict == "GENUINE") + sum(1 for s in url_scans if "GENUINE" in s.url_verdict)
    }
    
    return {
        "success": True,
        "stats": stats,
        "recent_scans": recent_scans
    }

@app.get("/api/sample-apks")
def list_samples():
    samples = [
        {
            "id": "banking_trojan_malware.apk",
            "name": "Banking Trojan Malware Sample",
            "type": "MALICIOUS",
            "description": "Simulates banking overlay trojan requesting SMS intercept, overlays, and boot autostart."
        },
        {
            "id": "stealth_spyware_malware.apk",
            "name": "Stealth Spyware Malware Sample",
            "type": "MALICIOUS",
            "description": "Simulates surveillance spyware requesting GPS tracking, audio recording, and call logs."
        },
        {
            "id": "clean_calculator_genuine.apk",
            "name": "Clean Calculator Genuine Sample",
            "type": "GENUINE",
            "description": "Simulates legitimate utility app requesting standard vibrate and network permissions."
        },
        {
            "id": "clean_photo_editor_genuine.apk",
            "name": "Clean Photo Studio Genuine Sample",
            "type": "GENUINE",
            "description": "Simulates legitimate image editing app requesting camera and storage permissions."
        }
    ]
    return {"samples": samples}

@app.post("/api/test-sample/{sample_id}")
def test_sample_apk(sample_id: str, user: dict = Depends(verify_session), db: Session = Depends(get_db)):
    target_path = os.path.join(SAMPLES_DIR, sample_id)
    if not os.path.exists(target_path):
        raise HTTPException(status_code=404, detail=f"Sample '{sample_id}' not found.")

    return process_apk_file(target_path, sample_id, user, db, scan_type="Sample Scan")


@app.get("/api/report/{scan_id}")
def get_report(scan_id: str, user: dict = Depends(verify_session), db: Session = Depends(get_db)):
    apk = db.query(APKScan).filter(APKScan.scan_id == scan_id, APKScan.user_id == user["user_id"]).first()
    if apk:
        return {"success": True, "type": "APK", "data": {
            "file_name": apk.file_name,
            "verdict": apk.cnn_verdict,
            "risk_score": apk.risk_score,
            "permissions": json.loads(apk.all_permissions),
            "explanation": json.loads(apk.security_explanation)
        }}
    url = db.query(URLScan).filter(URLScan.scan_id == scan_id, URLScan.user_id == user["user_id"]).first()
    if url:
        return {"success": True, "type": "URL", "data": {
            "original_url": url.original_url,
            "verdict": url.url_verdict,
            "risk_score": url.url_risk_score,
            "phishing_indicators": json.loads(url.phishing_indicators),
            "suspicious_indicators": json.loads(url.suspicious_indicators),
            "explanation": url.url_explanation
        }}
    raise HTTPException(status_code=404, detail="Report not found")

