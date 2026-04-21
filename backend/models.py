"""
Database models for Smart Contract Auditor AI
"""
from sqlalchemy import Column, String, Integer, DateTime, Text, Float, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime

Base = declarative_base()


class AuditJob(Base):
    __tablename__ = "audit_jobs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(String, default="anonymous")
    contract_name = Column(String, default="Unknown")
    contract_code = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    status = Column(String, default="pending")  # pending, processing, completed, failed
    risk_score = Column(Integer, default=0)
    total_vulnerabilities = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, autoincrement=True)
    audit_job_id = Column(Integer, nullable=False)
    vulnerability_type = Column(String)
    severity = Column(String)  # low, medium, high, critical
    line_number = Column(Integer)
    description = Column(Text)
    suggested_fix = Column(Text)
    confidence_score = Column(Float, default=0.0)
    created_at = Column(DateTime, default=datetime.utcnow)


def init_db(database_url: str = "sqlite:///./auditor.db"):
    """Initialize database and return engine + session"""
    engine = create_engine(database_url, echo=False)
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    return engine, SessionLocal
