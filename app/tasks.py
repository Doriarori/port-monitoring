import logging

logger = logging.getLogger(__name__)


def do_scan(scan_id: int, host: str, scan_type: str):
    from .database import SessionLocal
    from . import crud
    from .scanner import run_scan

    db = SessionLocal()
    try:
        scan = crud.get_scan(db, scan_id)
        if not scan:
            return
        scan.status = "running"
        db.commit()
        ports, error = run_scan(host, scan_type)
        crud.save_scan_results(db, scan, ports, error)
    except Exception as e:
        from .database import SessionLocal as SL
        db2 = SL()
        try:
            scan = crud.get_scan(db2, scan_id)
            if scan:
                crud.save_scan_results(db2, scan, [], str(e))
        finally:
            db2.close()
    finally:
        db.close()
