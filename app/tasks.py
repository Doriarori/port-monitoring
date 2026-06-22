import logging
import threading

logger = logging.getLogger(__name__)

_SCAN_SEM = threading.Semaphore(3)  # max 3 concurrent scans


def do_scan(scan_id: int, host: str, scan_type: str):
    from .database import SessionLocal
    from . import crud
    from .scanner import run_scan

    with _SCAN_SEM:
        db = SessionLocal()
        try:
            scan = crud.get_scan(db, scan_id)
            if not scan:
                return
            scan.status = "running"
            db.commit()
            ports, error = run_scan(host, scan_type)
            new_ports = crud.save_scan_results(db, scan, ports, error)
            if new_ports and not error:
                from .notifications import notify_new_ports
                notify_new_ports(db, scan.target_id, host, new_ports)
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
