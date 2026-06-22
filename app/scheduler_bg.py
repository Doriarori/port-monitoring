import json
import logging
import threading
from datetime import datetime, timedelta

from apscheduler.schedulers.background import BackgroundScheduler

logger = logging.getLogger(__name__)

INTERVALS: dict[str, timedelta] = {
    "hourly":  timedelta(hours=1),
    "daily":   timedelta(days=1),
    "weekly":  timedelta(weeks=1),
    "monthly": timedelta(days=30),
}

_scheduler = BackgroundScheduler(daemon=True)


def _check_and_run():
    from .database import SessionLocal
    from . import crud, models
    from .tasks import do_scan

    db = SessionLocal()
    try:
        now = datetime.utcnow()
        due = (
            db.query(models.Schedule)
            .filter(
                models.Schedule.is_active == True,
                models.Schedule.next_run_at != None,
                models.Schedule.next_run_at <= now,
            )
            .all()
        )

        for sched in due:
            target_ids: list[int] = json.loads(sched.target_ids or "[]")

            # Add targets matched by tag filter
            if sched.filter_tags:
                ftags = {t.strip() for t in sched.filter_tags.split(",") if t.strip()}
                all_targets = (
                    db.query(models.Target).filter(models.Target.is_active == True).all()
                )
                for t in all_targets:
                    t_tags = {x.strip() for x in (t.tags or "").split(",") if x.strip()}
                    if ftags & t_tags and t.id not in target_ids:
                        target_ids.append(t.id)

            for tid in target_ids:
                target = crud.get_target(db, tid)
                if not target or not target.is_active:
                    continue
                scan = crud.create_scan(db, tid, sched.scan_type)
                threading.Thread(
                    target=do_scan,
                    args=(scan.id, target.host, sched.scan_type),
                    daemon=True,
                ).start()

            sched.last_run_at = now
            sched.next_run_at = now + INTERVALS.get(sched.interval, timedelta(days=1))
            db.commit()
            logger.info("Schedule %d '%s' ran for %d targets", sched.id, sched.name, len(target_ids))

    except Exception as e:
        logger.error("Scheduler check error: %s", e)
    finally:
        db.close()


def _run_retention():
    from .database import SessionLocal
    from . import crud
    db = SessionLocal()
    try:
        days = int(crud.get_setting(db, "retention_days") or "90")
        deleted = crud.cleanup_old_scans(db, days)
        if deleted:
            logger.info("Retention cleanup: deleted %d old scans (keep_days=%d)", deleted, days)
    except Exception as e:
        logger.error("Retention cleanup error: %s", e)
    finally:
        db.close()


def start():
    if not _scheduler.running:
        _scheduler.add_job(_check_and_run, "interval", minutes=1,  id="sched_check",     replace_existing=True)
        _scheduler.add_job(_run_retention, "interval", hours=24,   id="sched_retention", replace_existing=True)
        _scheduler.start()
        logger.info("Background scheduler started")
