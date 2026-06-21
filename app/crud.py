import json
from datetime import datetime, timedelta
from sqlalchemy import func
from sqlalchemy.orm import Session
from . import models, schemas

INTERVALS: dict[str, timedelta] = {
    "hourly":  timedelta(hours=1),
    "daily":   timedelta(days=1),
    "weekly":  timedelta(weeks=1),
    "monthly": timedelta(days=30),
}


# ── Targets ───────────────────────────────────────────────────────────────────

def get_targets(db: Session, tag_filter: str | None = None) -> list[dict]:
    rows = db.query(models.Target).filter(models.Target.is_active == True).all()
    result = []
    for t in rows:
        if tag_filter:
            t_tags = {x.strip() for x in (t.tags or "").split(",") if x.strip()}
            if tag_filter not in t_tags:
                continue

        latest_completed = (
            db.query(models.Scan)
            .filter(models.Scan.target_id == t.id, models.Scan.status == "completed")
            .order_by(models.Scan.finished_at.desc())
            .first()
        )
        active_scan = (
            db.query(models.Scan)
            .filter(models.Scan.target_id == t.id, models.Scan.status.in_(["pending", "running"]))
            .order_by(models.Scan.started_at.desc())
            .first()
        )
        result.append({
            "id": t.id,
            "name": t.name,
            "host": t.host,
            "description": t.description,
            "tags": t.tags,
            "is_active": t.is_active,
            "created_at": t.created_at,
            "last_scan_at": latest_completed.finished_at if latest_completed else None,
            "last_scan_id": latest_completed.id if latest_completed else None,
            "open_ports_count": latest_completed.open_ports_count if latest_completed else 0,
            "active_scan_status": active_scan.status if active_scan else None,
            "active_scan_id": active_scan.id if active_scan else None,
        })
    return result


def get_target(db: Session, target_id: int) -> models.Target | None:
    return db.query(models.Target).filter(models.Target.id == target_id).first()


def create_target(db: Session, data: schemas.TargetCreate) -> models.Target:
    tags = _clean_tags(data.tags)
    target = models.Target(name=data.name, host=data.host, description=data.description, tags=tags)
    db.add(target)
    db.commit()
    db.refresh(target)
    return target


def update_target_tags(db: Session, target_id: int, tags: str) -> bool:
    target = get_target(db, target_id)
    if not target:
        return False
    target.tags = _clean_tags(tags)
    db.commit()
    return True


def delete_target(db: Session, target_id: int) -> bool:
    target = get_target(db, target_id)
    if not target:
        return False
    target.is_active = False
    db.commit()
    return True


def _clean_tags(raw: str | None) -> str | None:
    if not raw:
        return None
    cleaned = ",".join(t.strip() for t in raw.split(",") if t.strip())
    return cleaned or None


def get_all_tags(db: Session) -> list[str]:
    """Return sorted unique tags across all active targets."""
    rows = db.query(models.Target.tags).filter(
        models.Target.is_active == True, models.Target.tags != None
    ).all()
    tags: set[str] = set()
    for (tag_str,) in rows:
        for t in (tag_str or "").split(","):
            t = t.strip()
            if t:
                tags.add(t)
    return sorted(tags)


# ── Scans ─────────────────────────────────────────────────────────────────────

def create_scan(db: Session, target_id: int, scan_type: str) -> models.Scan:
    scan = models.Scan(target_id=target_id, scan_type=scan_type, status="pending")
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


def get_scans(db: Session, target_id: int | None = None, limit: int = 100) -> list[models.Scan]:
    q = db.query(models.Scan)
    if target_id:
        q = q.filter(models.Scan.target_id == target_id)
    return q.order_by(models.Scan.started_at.desc()).limit(limit).all()


def get_scan(db: Session, scan_id: int) -> models.Scan | None:
    return db.query(models.Scan).filter(models.Scan.id == scan_id).first()


def save_scan_results(db: Session, scan: models.Scan, ports: list[dict], error: str | None = None):
    now = datetime.utcnow()
    scan.finished_at = now
    if error:
        scan.status = "failed"
        scan.error_message = error
    else:
        scan.status = "completed"
        scan.open_ports_count = len(ports)
        for p in ports:
            db.add(models.OpenPort(
                scan_id=scan.id,
                port=p["port"],
                protocol=p["protocol"],
                state=p["state"],
                service=p.get("service"),
                product=p.get("product"),
                version=p.get("version"),
                extra_info=p.get("extra_info"),
            ))
        update_vulnerabilities(db, scan.target_id, ports, now)
    db.commit()


# ── Vulnerabilities ───────────────────────────────────────────────────────────

def update_vulnerabilities(db: Session, target_id: int, ports: list[dict], scan_time: datetime):
    current_keys = {(p["port"], p["protocol"]) for p in ports}
    active_vulns = (
        db.query(models.Vulnerability)
        .filter(models.Vulnerability.target_id == target_id, models.Vulnerability.is_active == True)
        .all()
    )
    active_map = {(v.port, v.protocol): v for v in active_vulns}

    for p in ports:
        key = (p["port"], p["protocol"])
        if key in active_map:
            v = active_map[key]
            v.last_seen_at = scan_time
            v.service = p.get("service")
            v.product = p.get("product")
            v.version = p.get("version")
        else:
            db.add(models.Vulnerability(
                target_id=target_id,
                port=p["port"],
                protocol=p["protocol"],
                service=p.get("service"),
                product=p.get("product"),
                version=p.get("version"),
                first_seen_at=scan_time,
                last_seen_at=scan_time,
                is_active=True,
            ))

    for key, v in active_map.items():
        if key not in current_keys:
            v.is_active = False


def get_vulnerabilities(
    db: Session,
    target_id: int | None = None,
    tag_filter: str | None = None,
    since_hours: int | None = None,
    active_only: bool = True,
) -> list[dict]:
    q = db.query(models.Vulnerability).join(
        models.Target, models.Vulnerability.target_id == models.Target.id
    )
    if active_only:
        q = q.filter(models.Vulnerability.is_active == True)
    if target_id:
        q = q.filter(models.Vulnerability.target_id == target_id)
    if since_hours:
        cutoff = datetime.utcnow() - timedelta(hours=since_hours)
        q = q.filter(models.Vulnerability.first_seen_at >= cutoff)

    vulns = q.order_by(models.Vulnerability.first_seen_at.desc()).all()

    result = []
    for v in vulns:
        # Tag filter is applied in Python
        if tag_filter and v.target:
            t_tags = {x.strip() for x in (v.target.tags or "").split(",") if x.strip()}
            if tag_filter not in t_tags:
                continue
        result.append({
            "id": v.id,
            "target_id": v.target_id,
            "target_name": v.target.name if v.target else None,
            "target_host": v.target.host if v.target else None,
            "target_tags": v.target.tags if v.target else None,
            "port": v.port,
            "protocol": v.protocol,
            "service": v.service,
            "product": v.product,
            "version": v.version,
            "first_seen_at": v.first_seen_at,
            "last_seen_at": v.last_seen_at,
            "is_active": v.is_active,
        })
    return result


# ── Stats ─────────────────────────────────────────────────────────────────────

def get_stats(db: Session) -> dict:
    total_targets = db.query(func.count(models.Target.id)).filter(models.Target.is_active == True).scalar()
    total_scans = db.query(func.count(models.Scan.id)).scalar()
    total_open_ports = db.query(func.sum(models.Scan.open_ports_count)).filter(
        models.Scan.status == "completed"
    ).scalar() or 0
    running_scans = db.query(func.count(models.Scan.id)).filter(
        models.Scan.status.in_(["pending", "running"])
    ).scalar()
    active_vulns = db.query(func.count(models.Vulnerability.id)).filter(
        models.Vulnerability.is_active == True
    ).scalar()
    return {
        "total_targets": total_targets,
        "total_scans": total_scans,
        "total_open_ports": int(total_open_ports),
        "running_scans": running_scans,
        "active_vulns": active_vulns,
    }


# ── Schedules ─────────────────────────────────────────────────────────────────

def get_schedules(db: Session) -> list[models.Schedule]:
    return db.query(models.Schedule).order_by(models.Schedule.created_at.desc()).all()


def get_schedule(db: Session, schedule_id: int) -> models.Schedule | None:
    return db.query(models.Schedule).filter(models.Schedule.id == schedule_id).first()


def create_schedule(db: Session, data: schemas.ScheduleCreate) -> models.Schedule:
    now = datetime.utcnow()
    sched = models.Schedule(
        name=data.name,
        target_ids=json.dumps(data.target_ids),
        filter_tags=_clean_tags(data.filter_tags),
        scan_type=data.scan_type,
        interval=data.interval,
        is_active=True,
        next_run_at=now + INTERVALS[data.interval],
    )
    db.add(sched)
    db.commit()
    db.refresh(sched)
    return sched


def toggle_schedule(db: Session, schedule_id: int) -> models.Schedule | None:
    sched = get_schedule(db, schedule_id)
    if not sched:
        return None
    sched.is_active = not sched.is_active
    if sched.is_active and (sched.next_run_at is None or sched.next_run_at < datetime.utcnow()):
        sched.next_run_at = datetime.utcnow() + INTERVALS.get(sched.interval, timedelta(days=1))
    db.commit()
    return sched


def delete_schedule(db: Session, schedule_id: int) -> bool:
    sched = get_schedule(db, schedule_id)
    if not sched:
        return False
    db.delete(sched)
    db.commit()
    return True


def trigger_schedule_now(db: Session, schedule_id: int) -> int:
    """Force-run a schedule immediately. Returns count of scans launched."""
    from .tasks import do_scan
    import threading

    sched = get_schedule(db, schedule_id)
    if not sched:
        return 0

    target_ids: list[int] = json.loads(sched.target_ids or "[]")
    if sched.filter_tags:
        ftags = {t.strip() for t in sched.filter_tags.split(",") if t.strip()}
        all_targets = db.query(models.Target).filter(models.Target.is_active == True).all()
        for t in all_targets:
            t_tags = {x.strip() for x in (t.tags or "").split(",") if x.strip()}
            if ftags & t_tags and t.id not in target_ids:
                target_ids.append(t.id)

    count = 0
    now = datetime.utcnow()
    for tid in target_ids:
        target = get_target(db, tid)
        if not target or not target.is_active:
            continue
        scan = create_scan(db, tid, sched.scan_type)
        threading.Thread(target=do_scan, args=(scan.id, target.host, sched.scan_type), daemon=True).start()
        count += 1

    sched.last_run_at = now
    sched.next_run_at = now + INTERVALS.get(sched.interval, timedelta(days=1))
    db.commit()
    return count
