import os
from sqlalchemy import create_engine, Column, Integer, String, Float, Text, Boolean, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "appshield.db")
SQLALCHEMY_DATABASE_URL = f"sqlite:///{DB_PATH}"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

class APKScan(Base):
    __tablename__ = "apk_scans"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(String, index=True)
    scan_id = Column(String, index=True, unique=True)
    file_name = Column(String)
    file_size = Column(Float)
    app_name = Column(String)
    package_name = Column(String)
    version = Column(String)
    version_code = Column(String)
    sha256 = Column(String)
    sha1 = Column(String)
    scan_type = Column(String)
    cnn_verdict = Column(String)
    confidence = Column(Float)
    risk_score = Column(Float)
    safety_score = Column(Float)
    all_permissions = Column(Text)
    dangerous_permissions = Column(Text)
    permission_risk = Column(String)
    security_explanation = Column(Text)
    recommendations = Column(Text)
    timestamp = Column(DateTime, default=datetime.utcnow)

class URLScan(Base):
    __tablename__ = "url_scans"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(String, index=True)
    scan_id = Column(String, index=True, unique=True)
    original_url = Column(String)
    final_url = Column(String)
    domain = Column(String)
    protocol = Column(String)
    https_status = Column(Boolean)
    redirects = Column(Integer)
    url_risk_score = Column(Float)
    url_verdict = Column(String)
    phishing_indicators = Column(Text)
    suspicious_indicators = Column(Text)
    url_explanation = Column(Text)
    timestamp = Column(DateTime, default=datetime.utcnow)

class ReputationData(Base):
    __tablename__ = "reputation_data"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(String, index=True)
    scan_id = Column(String, index=True, unique=True)
    signature_info = Column(Text)
    certificate_info = Column(Text)
    threat_intelligence = Column(Text)
    package_history = Column(Text)
    reputation_score = Column(Float)
    reputation_level = Column(String)
    explanation = Column(Text)
    timestamp = Column(DateTime, default=datetime.utcnow)
    package_name = Column(String, index=True)
    sha256 = Column(String, index=True)

Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
