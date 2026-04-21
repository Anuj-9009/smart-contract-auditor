"""
FastAPI Backend — Smart Contract Auditor AI
Zero-cost stack: Ollama/Groq + Supabase/SQLite
"""
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List
import os
import json
from datetime import datetime, timezone
from dotenv import load_dotenv

load_dotenv()

# ─── Database Layer (Supabase or SQLite fallback) ────────────────────────────

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_ANON_KEY")
use_supabase = bool(SUPABASE_URL and SUPABASE_KEY)

if use_supabase:
    from supabase import create_client
    supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
    print(f"  ✓ Database: Supabase ({SUPABASE_URL[:40]}...)")
else:
    # SQLite fallback for local dev
    from models import init_db, AuditJob, Vulnerability
    DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./auditor.db")
    engine, SessionLocal = init_db(DATABASE_URL)
    supabase = None
    print(f"  ✓ Database: SQLite (local)")


class DBLayer:
    """Abstraction over Supabase and SQLite so the API code stays clean."""

    @staticmethod
    def insert_audit_job(contract_name: str, contract_code: str) -> int:
        if use_supabase:
            result = supabase.table("audit_jobs").insert({
                "contract_name": contract_name,
                "contract_code": contract_code,
                "status": "processing",
                "created_at": datetime.now(timezone.utc).isoformat(),
            }).execute()
            return result.data[0]["id"]
        else:
            db = SessionLocal()
            job = AuditJob(contract_name=contract_name, contract_code=contract_code, status="processing")
            db.add(job)
            db.commit()
            db.refresh(job)
            job_id = job.id
            db.close()
            return job_id

    @staticmethod
    def update_audit_job(job_id: int, data: dict):
        if use_supabase:
            supabase.table("audit_jobs").update(data).eq("id", job_id).execute()
        else:
            db = SessionLocal()
            job = db.query(AuditJob).filter(AuditJob.id == job_id).first()
            if job:
                for k, v in data.items():
                    setattr(job, k, v)
                db.commit()
            db.close()

    @staticmethod
    def insert_vulnerability(job_id: int, vuln: dict):
        if use_supabase:
            supabase.table("vulnerabilities").insert({
                "audit_job_id": job_id,
                "vulnerability_type": vuln.get("type"),
                "severity": vuln.get("severity"),
                "line_number": vuln.get("line"),
                "description": vuln.get("description"),
                "suggested_fix": vuln.get("fix"),
                "confidence_score": vuln.get("confidence", 0),
                "created_at": datetime.now(timezone.utc).isoformat(),
            }).execute()
        else:
            db = SessionLocal()
            db_vuln = Vulnerability(
                audit_job_id=job_id,
                vulnerability_type=vuln.get("type"),
                severity=vuln.get("severity"),
                line_number=vuln.get("line"),
                description=vuln.get("description"),
                suggested_fix=vuln.get("fix"),
                confidence_score=vuln.get("confidence", 0),
            )
            db.add(db_vuln)
            db.commit()
            db.close()

    @staticmethod
    def get_audit_job(job_id: int) -> Optional[dict]:
        if use_supabase:
            result = supabase.table("audit_jobs").select("*").eq("id", job_id).execute()
            return result.data[0] if result.data else None
        else:
            db = SessionLocal()
            job = db.query(AuditJob).filter(AuditJob.id == job_id).first()
            if not job:
                db.close()
                return None
            data = {
                "id": job.id, "contract_name": job.contract_name,
                "status": job.status, "risk_score": job.risk_score,
                "total_vulnerabilities": job.total_vulnerabilities,
                "critical_count": job.critical_count, "created_at": job.created_at.isoformat() if job.created_at else None,
            }
            db.close()
            return data

    @staticmethod
    def get_vulnerabilities(job_id: int) -> List[dict]:
        if use_supabase:
            result = supabase.table("vulnerabilities").select("*").eq("audit_job_id", job_id).execute()
            return [{
                "type": v["vulnerability_type"], "severity": v["severity"],
                "line": v["line_number"], "description": v["description"],
                "fix": v["suggested_fix"], "confidence": v["confidence_score"],
            } for v in result.data]
        else:
            db = SessionLocal()
            vulns = db.query(Vulnerability).filter(Vulnerability.audit_job_id == job_id).all()
            data = [{
                "type": v.vulnerability_type, "severity": v.severity,
                "line": v.line_number, "description": v.description,
                "fix": v.suggested_fix, "confidence": v.confidence_score,
            } for v in vulns]
            db.close()
            return data

    @staticmethod
    def get_history(limit: int = 20) -> List[dict]:
        if use_supabase:
            result = (supabase.table("audit_jobs").select("*")
                      .order("created_at", desc=True).limit(limit).execute())
            return [{
                "job_id": j["id"], "contract_name": j.get("contract_name", "Unknown"),
                "status": j["status"], "risk_score": j.get("risk_score", 0),
                "total_vulnerabilities": j.get("total_vulnerabilities", 0),
                "critical_count": j.get("critical_count", 0),
                "created_at": j.get("created_at"),
            } for j in result.data]
        else:
            db = SessionLocal()
            jobs = db.query(AuditJob).order_by(AuditJob.created_at.desc()).limit(limit).all()
            data = [{
                "job_id": j.id, "contract_name": j.contract_name,
                "status": j.status, "risk_score": j.risk_score,
                "total_vulnerabilities": j.total_vulnerabilities,
                "critical_count": j.critical_count,
                "created_at": j.created_at.isoformat() if j.created_at else None,
            } for j in jobs]
            db.close()
            return data

    @staticmethod
    def get_stats() -> dict:
        if use_supabase:
            audits = supabase.table("audit_jobs").select("id", count="exact").eq("status", "completed").execute()
            vulns = supabase.table("vulnerabilities").select("id", count="exact").execute()
            critical = supabase.table("vulnerabilities").select("id", count="exact").eq("severity", "critical").execute()
            high = supabase.table("vulnerabilities").select("id", count="exact").eq("severity", "high").execute()
            return {
                "total_audits": audits.count or 0,
                "total_vulnerabilities": vulns.count or 0,
                "critical_count": critical.count or 0,
                "high_count": high.count or 0,
            }
        else:
            db = SessionLocal()
            total_audits = db.query(AuditJob).filter(AuditJob.status == "completed").count()
            total_vulns = db.query(Vulnerability).count()
            critical = db.query(Vulnerability).filter(Vulnerability.severity == "critical").count()
            high = db.query(Vulnerability).filter(Vulnerability.severity == "high").count()
            db.close()
            return {
                "total_audits": total_audits,
                "total_vulnerabilities": total_vulns,
                "critical_count": critical,
                "high_count": high,
            }


# ─── Audit Engine ────────────────────────────────────────────────────────────

from auditor.engine import SmartContractAuditor
from auditor.sample_contracts import SAMPLE_CONTRACTS, SAMPLE_LIST

auditor = SmartContractAuditor()
db = DBLayer()

# ─── FastAPI App ─────────────────────────────────────────────────────────────

app = FastAPI(title="Smart Contract Auditor AI", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class AuditRequest(BaseModel):
    contract_code: str
    contract_name: str = "Unknown"
    mode: str = "full"


# ─── Endpoints ───────────────────────────────────────────────────────────────

@app.get("/api/health")
async def health():
    return {
        "status": "healthy",
        "version": "2.0.0",
        "llm_provider": auditor.provider_name,
        "llm_enabled": auditor.llm_enabled,
        "database": "supabase" if use_supabase else "sqlite",
    }


@app.post("/api/audit")
async def audit_contract(request: AuditRequest):
    if not request.contract_code.strip():
        raise HTTPException(400, "Contract code cannot be empty")

    try:
        job_id = db.insert_audit_job(request.contract_name, request.contract_code)
        result = auditor.audit_contract(request.contract_code, mode=request.mode)
        report = auditor.generate_report(result)

        for vuln in result.get("vulnerabilities", []):
            db.insert_vulnerability(job_id, vuln)

        db.update_audit_job(job_id, {
            "status": "completed",
            "risk_score": result.get("risk_score", 0),
            "total_vulnerabilities": result.get("total_found", 0),
            "critical_count": result.get("critical_count", 0),
            "high_count": result.get("high_count", 0),
            "medium_count": result.get("medium_count", 0),
            "low_count": result.get("low_count", 0),
        })

        return {
            "job_id": job_id,
            "status": "completed",
            **result,
            "report": report,
        }

    except Exception as e:
        try:
            db.update_audit_job(job_id, {"status": "failed"})
        except Exception:
            pass
        raise HTTPException(500, str(e))


@app.get("/api/audit/{job_id}")
async def get_audit(job_id: int):
    job = db.get_audit_job(job_id)
    if not job:
        raise HTTPException(404, "Audit not found")
    job["vulnerabilities"] = db.get_vulnerabilities(job_id)
    return job


@app.get("/api/history")
async def get_history(limit: int = 20):
    return {"audits": db.get_history(limit)}


@app.get("/api/stats")
async def get_stats():
    return db.get_stats()


@app.get("/api/samples")
async def get_samples():
    return {"samples": SAMPLE_LIST}


@app.get("/api/samples/{sample_id}")
async def get_sample(sample_id: str):
    if sample_id not in SAMPLE_CONTRACTS:
        raise HTTPException(404, "Sample not found")
    s = SAMPLE_CONTRACTS[sample_id]
    return {"id": sample_id, "name": s["name"], "description": s["description"], "code": s["code"]}


if __name__ == "__main__":
    import uvicorn
    print("\n🛡️  Smart Contract Auditor AI v2.0")
    print(f"  ✓ LLM: {auditor.provider_name} ({'active' if auditor.llm_enabled else 'pattern-only'})")
    print(f"  ✓ DB:  {'Supabase' if use_supabase else 'SQLite'}")
    print(f"  ✓ API: http://localhost:8000/docs\n")
    uvicorn.run(app, host="0.0.0.0", port=8000)
