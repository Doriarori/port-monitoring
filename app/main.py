from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
import os

from .database import engine, get_db, Base
from . import crud, schemas, models
from .tasks import do_scan

Base.metadata.create_all(bind=engine)


@asynccontextmanager
async def lifespan(app: FastAPI):
    from .scheduler_bg import start as start_scheduler
    start_scheduler()
    yield


app = FastAPI(title="Port Monitor", version="1.0.0", docs_url="/api/docs", lifespan=lifespan)

FRONTEND_DIR = os.path.join(os.path.dirname(__file__), "..", "frontend")


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

@app.get("/api/vulnerabilities", response_model=list[schemas.VulnerabilityOut])
def list_vulnerabilities(
    target_id: int | None = None,
    tag: str | None = None,
    since_hours: int | None = None,
    active_only: bool = True,
    db: Session = Depends(get_db),
):
    return crud.get_vulnerabilities(db, target_id=target_id, tag_filter=tag, since_hours=since_hours, active_only=active_only)


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


# ── Frontend ──────────────────────────────────────────────────────────────────

@app.get("/", include_in_schema=False)
def serve_ui():
    return FileResponse(os.path.join(FRONTEND_DIR, "index.html"))
