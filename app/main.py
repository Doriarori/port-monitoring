import csv
import io
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, Request
from fastapi.responses import FileResponse, StreamingResponse, JSONResponse
from sqlalchemy import text
from sqlalchemy.orm import Session
import os

from .database import engine, get_db, Base
from . import crud, schemas, models, auth
from .tasks import do_scan

Base.metadata.create_all(bind=engine)


def _migrate():
    """Add columns introduced after initial schema creation."""
    with engine.connect() as conn:
        conn.execute(text("""
            ALTER TABLE vulnerabilities
                ADD COLUMN IF NOT EXISTS severity        VARCHAR(16) NOT NULL DEFAULT 'info',
                ADD COLUMN IF NOT EXISTS is_acknowledged BOOLEAN     NOT NULL DEFAULT FALSE,
                ADD COLUMN IF NOT EXISTS acknowledged_at TIMESTAMP,
                ADD COLUMN IF NOT EXISTS acknowledged_note TEXT
        """))
        conn.commit()


@asynccontextmanager
async def lifespan(app: FastAPI):
    from .logging_config import setup as setup_logging
    setup_logging()
    _migrate()
    from .scheduler_bg import start as start_scheduler
    start_scheduler()
    yield


app = FastAPI(title="Port Monitor", version="1.0.0", docs_url="/api/docs", lifespan=lifespan)

FRONTEND_DIR = os.path.join(os.path.dirname(__file__), "..", "frontend")


# ── Auth ────────────────────────────────────────────────────────────────────

@app.middleware("http")
async def auth_guard(request: Request, call_next):
    """Require a valid bearer token for protected /api endpoints."""
    if request.method == "OPTIONS" or not auth.requires_auth(request.url.path):
        return await call_next(request)
    try:
        token = auth.token_from_header(request.headers.get("Authorization"))
        auth.verify_token(token)
    except auth.AuthError as e:
        return JSONResponse({"detail": e.detail}, status_code=401)
    return await call_next(request)


@app.get("/api/auth/config", include_in_schema=False)
def auth_config():
    """Public: lets the UI know whether to show the login screen."""
    return {"auth_enabled": auth.AUTH_ENABLED and auth.is_configured()}


@app.post("/api/auth/login")
def login(body: schemas.LoginRequest):
    if not auth.authenticate(body.username, body.password):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    token = auth.create_access_token(body.username)
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": auth.JWT_EXPIRE_MINUTES * 60,
    }


@app.get("/api/auth/me")
def auth_me():
    """Protected by the middleware — a 200 here confirms the token is valid."""
    return {"username": auth.ADMIN_USERNAME}


# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/health", include_in_schema=False)
def health(db: Session = Depends(get_db)):
    try:
        db.execute(text("SELECT 1"))
        return {"status": "ok", "db": "ok"}
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"DB error: {e}")


# ── Targets ───────────────────────────────────────────────────────────────────

@app.get("/api/targets", response_model=list[schemas.TargetOut])
def list_targets(tag: str | None = None, db: Session = Depends(get_db)):
    return crud.get_targets(db, tag_filter=tag)


@app.post("/api/targets", response_model=schemas.TargetOut, status_code=201)
def add_target(body: schemas.TargetCreate, db: Session = Depends(get_db)):
    existing = db.query(models.Target).filter(models.Target.host == body.host).first()
    if existing and existing.is_active:
        raise HTTPException(status_code=409, detail="Target with this host already exists")
    target = crud.create_target(db, body)
    return {
        "id": target.id, "name": target.name, "host": target.host,
        "description": target.description, "tags": target.tags,
        "is_active": target.is_active, "created_at": target.created_at,
        "last_scan_at": None, "last_scan_id": None, "open_ports_count": 0,
    }


@app.patch("/api/targets/{target_id}/tags", status_code=204)
def update_tags(target_id: int, body: dict, db: Session = Depends(get_db)):
    if not crud.update_target_tags(db, target_id, body.get("tags", "")):
        raise HTTPException(status_code=404, detail="Target not found")


@app.delete("/api/targets/{target_id}", status_code=204)
def remove_target(target_id: int, db: Session = Depends(get_db)):
    if not crud.delete_target(db, target_id):
        raise HTTPException(status_code=404, detail="Target not found")


@app.get("/api/tags")
def list_tags(db: Session = Depends(get_db)) -> list[str]:
    return crud.get_all_tags(db)


# ── Scans ─────────────────────────────────────────────────────────────────────

@app.post("/api/targets/{target_id}/scan", response_model=schemas.ScanOut, status_code=202)
def start_scan(
    target_id: int,
    body: schemas.ScanCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
):
    target = crud.get_target(db, target_id)
    if not target or not target.is_active:
        raise HTTPException(status_code=404, detail="Target not found")
    scan = crud.create_scan(db, target_id, body.scan_type)
    background_tasks.add_task(do_scan, scan.id, target.host, body.scan_type)
    return schemas.ScanOut(
        id=scan.id, target_id=target_id,
        target_name=target.name, target_host=target.host,
        started_at=scan.started_at, finished_at=None,
        status=scan.status, scan_type=scan.scan_type,
        open_ports_count=0, error_message=None,
    )


@app.get("/api/scans/export")
def export_scans(format: str = "json", limit: int = 5000, db: Session = Depends(get_db)):
    scans = crud.get_scans(db, limit=limit)
    rows = [
        {
            "id": s.id, "target_name": s.target.name if s.target else None,
            "target_host": s.target.host if s.target else None,
            "scan_type": s.scan_type, "status": s.status,
            "started_at": str(s.started_at), "finished_at": str(s.finished_at) if s.finished_at else None,
            "open_ports_count": s.open_ports_count, "error_message": s.error_message,
        }
        for s in scans
    ]
    if format == "csv":
        output = io.StringIO()
        if rows:
            writer = csv.DictWriter(output, fieldnames=rows[0].keys())
            writer.writeheader()
            writer.writerows(rows)
        output.seek(0)
        return StreamingResponse(
            iter([output.read()]),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=scans.csv"},
        )
    return rows


@app.get("/api/scans", response_model=list[schemas.ScanOut])
def list_scans(target_id: int | None = None, limit: int = 100, db: Session = Depends(get_db)):
    scans = crud.get_scans(db, target_id=target_id, limit=limit)
    return [schemas.ScanOut(
        id=s.id, target_id=s.target_id,
        target_name=s.target.name if s.target else None,
        target_host=s.target.host if s.target else None,
        started_at=s.started_at, finished_at=s.finished_at,
        status=s.status, scan_type=s.scan_type,
        open_ports_count=s.open_ports_count, error_message=s.error_message,
    ) for s in scans]


@app.get("/api/scans/{scan_id}/diff")
def scan_diff(scan_id: int, db: Session = Depends(get_db)):
    result = crud.get_scan_diff(db, scan_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return result


@app.get("/api/scans/{scan_id}", response_model=schemas.ScanOut)
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = crud.get_scan(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return schemas.ScanOut(
        id=scan.id, target_id=scan.target_id,
        target_name=scan.target.name if scan.target else None,
        target_host=scan.target.host if scan.target else None,
        started_at=scan.started_at, finished_at=scan.finished_at,
        status=scan.status, scan_type=scan.scan_type,
        open_ports_count=scan.open_ports_count, error_message=scan.error_message,
        ports=[schemas.OpenPortOut(
            id=p.id, port=p.port, protocol=p.protocol, state=p.state,
            service=p.service, product=p.product, version=p.version, extra_info=p.extra_info,
        ) for p in scan.ports],
    )


# ── Vulnerabilities ───────────────────────────────────────────────────────────

@app.get("/api/vulnerabilities/export")
def export_vulnerabilities(
    format: str = "json",
    active_only: bool = True,
    severity: str | None = None,
    db: Session = Depends(get_db),
):
    vulns = crud.get_vulnerabilities(db, active_only=active_only, severity=severity, limit=10000)
    rows = [
        {
            "id": v["id"], "target_name": v["target_name"], "target_host": v["target_host"],
            "target_tags": v["target_tags"], "port": v["port"], "protocol": v["protocol"],
            "service": v["service"], "product": v["product"], "version": v["version"],
            "severity": v["severity"], "is_acknowledged": v["is_acknowledged"],
            "acknowledged_note": v["acknowledged_note"],
            "first_seen_at": str(v["first_seen_at"]), "last_seen_at": str(v["last_seen_at"]),
        }
        for v in vulns
    ]
    if format == "csv":
        output = io.StringIO()
        if rows:
            writer = csv.DictWriter(output, fieldnames=rows[0].keys())
            writer.writeheader()
            writer.writerows(rows)
        output.seek(0)
        return StreamingResponse(
            iter([output.read()]),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=vulnerabilities.csv"},
        )
    return rows


@app.get("/api/vulnerabilities", response_model=list[schemas.VulnerabilityOut])
def list_vulnerabilities(
    target_id: int | None = None,
    tag: str | None = None,
    since_hours: int | None = None,
    active_only: bool = True,
    severity: str | None = None,
    acknowledged: bool | None = None,
    limit: int = 1000,
    offset: int = 0,
    db: Session = Depends(get_db),
):
    return crud.get_vulnerabilities(
        db, target_id=target_id, tag_filter=tag, since_hours=since_hours,
        active_only=active_only, severity=severity, acknowledged=acknowledged,
        limit=limit, offset=offset,
    )


@app.post("/api/vulnerabilities/{vuln_id}/acknowledge", status_code=200)
def acknowledge_vuln(vuln_id: int, body: dict = {}, db: Session = Depends(get_db)):
    if not crud.acknowledge_vulnerability(db, vuln_id, body.get("note")):
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    return {"ok": True}


@app.delete("/api/vulnerabilities/{vuln_id}/acknowledge", status_code=200)
def unacknowledge_vuln(vuln_id: int, db: Session = Depends(get_db)):
    if not crud.unacknowledge_vulnerability(db, vuln_id):
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    return {"ok": True}


# ── Stats ─────────────────────────────────────────────────────────────────────

@app.get("/api/stats", response_model=schemas.StatsOut)
def get_stats(db: Session = Depends(get_db)):
    return crud.get_stats(db)


# ── Schedules ─────────────────────────────────────────────────────────────────

@app.get("/api/schedules", response_model=list[schemas.ScheduleOut])
def list_schedules(db: Session = Depends(get_db)):
    return crud.get_schedules(db)


@app.post("/api/schedules", response_model=schemas.ScheduleOut, status_code=201)
def create_schedule(body: schemas.ScheduleCreate, db: Session = Depends(get_db)):
    return crud.create_schedule(db, body)


@app.post("/api/schedules/{schedule_id}/toggle", response_model=schemas.ScheduleOut)
def toggle_schedule(schedule_id: int, db: Session = Depends(get_db)):
    sched = crud.toggle_schedule(db, schedule_id)
    if not sched:
        raise HTTPException(status_code=404, detail="Schedule not found")
    return sched


@app.post("/api/schedules/{schedule_id}/run", status_code=202)
def run_schedule_now(schedule_id: int, db: Session = Depends(get_db)):
    count = crud.trigger_schedule_now(db, schedule_id)
    return {"launched": count}


@app.delete("/api/schedules/{schedule_id}", status_code=204)
def delete_schedule(schedule_id: int, db: Session = Depends(get_db)):
    if not crud.delete_schedule(db, schedule_id):
        raise HTTPException(status_code=404, detail="Schedule not found")


# ── Settings ──────────────────────────────────────────────────────────────────

SETTINGS_KEYS = {
    "slack_webhook_url", "slack_notify_new_ports",
    "webhook_url", "webhook_notify_new_ports",
    "smtp_host", "smtp_port", "smtp_user", "smtp_pass", "smtp_to", "smtp_tls",
    "smtp_notify_new_ports",
    "theme",
    "retention_days",
}


@app.get("/api/settings")
def get_settings(db: Session = Depends(get_db)):
    s = crud.get_all_settings(db)
    # Never expose smtp password in plaintext
    if "smtp_pass" in s and s["smtp_pass"]:
        s["smtp_pass"] = "●●●●●●●●"
    return s


@app.post("/api/settings")
def save_settings(body: dict, db: Session = Depends(get_db)):
    for k, v in body.items():
        if k not in SETTINGS_KEYS:
            continue
        # Don't overwrite password if placeholder sent back
        if k == "smtp_pass" and v == "●●●●●●●●":
            continue
        crud.set_setting(db, k, v if v is not None else None)
    return {"ok": True}


@app.post("/api/settings/test-slack")
def test_slack(body: dict, db: Session = Depends(get_db)):
    from .notifications import send_slack_message
    webhook_url = body.get("webhook_url") or crud.get_setting(db, "slack_webhook_url")
    if not webhook_url:
        raise HTTPException(status_code=400, detail="Webhook URL not set")
    try:
        send_slack_message(webhook_url, ":white_check_mark: *Port Monitor*: test message — integration working!")
        return {"ok": True}
    except RuntimeError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/settings/test-webhook")
def test_webhook(body: dict, db: Session = Depends(get_db)):
    from .notifications import send_webhook_message
    from datetime import datetime, timezone
    url = body.get("webhook_url") or crud.get_setting(db, "webhook_url")
    if not url:
        raise HTTPException(status_code=400, detail="Webhook URL not set")
    try:
        send_webhook_message(url, {
            "event": "test",
            "message": "Port Monitor — test notification",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        return {"ok": True}
    except RuntimeError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/settings/test-email")
def test_email(body: dict, db: Session = Depends(get_db)):
    from .notifications import send_email
    smtp_host = body.get("smtp_host") or crud.get_setting(db, "smtp_host")
    smtp_to   = body.get("smtp_to")   or crud.get_setting(db, "smtp_to")
    if not smtp_host or not smtp_to:
        raise HTTPException(status_code=400, detail="SMTP host and recipient are required")
    smtp_pass = body.get("smtp_pass") or ""
    if smtp_pass == "●●●●●●●●":
        smtp_pass = crud.get_setting(db, "smtp_pass") or ""
    try:
        send_email(
            smtp_host=smtp_host,
            smtp_port=int(body.get("smtp_port") or crud.get_setting(db, "smtp_port") or "587"),
            smtp_user=body.get("smtp_user") or crud.get_setting(db, "smtp_user") or "",
            smtp_pass=smtp_pass,
            to_addr=smtp_to,
            subject="[Port Monitor] Test notification",
            body="This is a test email from Port Monitor. Your email integration is working correctly.",
            use_tls=(body.get("smtp_tls") or crud.get_setting(db, "smtp_tls") or "true") != "false",
        )
        return {"ok": True}
    except RuntimeError as e:
        raise HTTPException(status_code=400, detail=str(e))


# ── Frontend ──────────────────────────────────────────────────────────────────

@app.get("/", include_in_schema=False)
def serve_ui():
    return FileResponse(os.path.join(FRONTEND_DIR, "index.html"))
