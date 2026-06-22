from datetime import datetime
from pydantic import BaseModel, field_validator
import ipaddress
import re


# ── Auth ─────────────────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    username: str
    password: str


# ── Targets ──────────────────────────────────────────────────────────────────

class TargetCreate(BaseModel):
    name: str
    host: str
    description: str | None = None
    tags: str | None = None   # comma-separated, e.g. "production,web"

    @field_validator("host")
    @classmethod
    def validate_host(cls, v: str) -> str:
        v = v.strip().rstrip("/")
        # strip scheme if user pasted a URL
        for scheme in ("https://", "http://"):
            if v.lower().startswith(scheme):
                v = v[len(scheme):]
                break
        # strip port suffix
        if re.match(r"^[\w.\-]+:\d+$", v):
            v = v.rsplit(":", 1)[0]
        try:
            ipaddress.ip_address(v)
            return v
        except ValueError:
            pass
        if re.match(r"^[a-zA-Z0-9._-]+$", v):
            return v
        raise ValueError(f"Неверный хост: '{v}'. Укажите IP или hostname без http://")


class TargetOut(BaseModel):
    id: int
    name: str
    host: str
    description: str | None
    tags: str | None = None
    is_active: bool
    created_at: datetime
    last_scan_at: datetime | None = None
    last_scan_id: int | None = None
    open_ports_count: int = 0
    active_scan_status: str | None = None
    active_scan_id: int | None = None

    model_config = {"from_attributes": True}


# ── Scans ─────────────────────────────────────────────────────────────────────

class ScanCreate(BaseModel):
    scan_type: str = "tcp"

    @field_validator("scan_type")
    @classmethod
    def validate_type(cls, v: str) -> str:
        if v not in ("tcp", "udp", "both"):
            raise ValueError("scan_type must be tcp, udp, or both")
        return v


class OpenPortOut(BaseModel):
    id: int
    port: int
    protocol: str
    state: str
    service: str | None
    product: str | None
    version: str | None
    extra_info: str | None

    model_config = {"from_attributes": True}


class ScanOut(BaseModel):
    id: int
    target_id: int
    target_name: str | None = None
    target_host: str | None = None
    started_at: datetime
    finished_at: datetime | None
    status: str
    scan_type: str
    open_ports_count: int
    error_message: str | None
    ports: list[OpenPortOut] = []

    model_config = {"from_attributes": True}


# ── Vulnerabilities ───────────────────────────────────────────────────────────

class VulnerabilityOut(BaseModel):
    id: int
    target_id: int
    target_name: str | None = None
    target_host: str | None = None
    target_tags: str | None = None
    port: int
    protocol: str
    service: str | None
    product: str | None
    version: str | None
    first_seen_at: datetime
    last_seen_at: datetime
    is_active: bool
    severity: str = "info"
    is_acknowledged: bool = False
    acknowledged_at: datetime | None = None
    acknowledged_note: str | None = None

    model_config = {"from_attributes": True}


# ── Stats ─────────────────────────────────────────────────────────────────────

class StatsOut(BaseModel):
    total_targets: int
    total_scans: int
    total_open_ports: int
    running_scans: int
    active_vulns: int = 0


# ── Schedules ─────────────────────────────────────────────────────────────────

class ScheduleCreate(BaseModel):
    name: str
    target_ids: list[int] = []
    filter_tags: str | None = None
    scan_type: str = "tcp"
    interval: str = "daily"

    @field_validator("scan_type")
    @classmethod
    def val_scan_type(cls, v: str) -> str:
        if v not in ("tcp", "udp", "both"):
            raise ValueError("invalid scan_type")
        return v

    @field_validator("interval")
    @classmethod
    def val_interval(cls, v: str) -> str:
        if v not in ("hourly", "daily", "weekly", "monthly"):
            raise ValueError("invalid interval")
        return v


class ScheduleOut(BaseModel):
    id: int
    name: str
    target_ids: str
    filter_tags: str | None
    scan_type: str
    interval: str
    is_active: bool
    next_run_at: datetime | None
    last_run_at: datetime | None
    created_at: datetime

    model_config = {"from_attributes": True}
