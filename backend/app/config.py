"""Application configuration.

Non-secret configuration arrives via environment variables; secrets arrive via
read-only mounted files (Docker secret style). All values are validated at
startup. Never read secret files into logs.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Annotated
from urllib.parse import urlparse

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# env_file is resolved to the repo-root .env so every invocation works no
# matter the working directory (alembic, pytest and uvicorn all run from
# backend/; tasks.ps1 and Makefile call them with backend as CWD).
_APP_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _APP_DIR.parent.parent
_REPO_ENV_FILE = _REPO_ROOT / ".env"


class WardenSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="WARDEN_",
        env_file=_REPO_ENV_FILE,
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Runtime identity
    app_env: str = Field(default="production")
    public_url: str = Field(default="http://localhost")
    display_timezone: str = Field(default="Asia/Shanghai")

    # Authentication and sessions (docs/SECURITY.md §2, API_CONTRACT.md §11)
    session_idle_minutes: int = Field(default=30, ge=1)
    session_absolute_hours: int = Field(default=12, ge=1)
    reauth_ttl_minutes: int = Field(default=5, ge=1)
    login_lockout_after_failures: int = Field(default=5, ge=1)
    login_lockout_minutes: int = Field(default=15, ge=1)
    login_rate_limit_per_minute: int = Field(default=5, ge=1)
    session_rate_limit_per_minute: int = Field(default=300, ge=1)
    probe_rate_limit_per_minute: int = Field(default=10, ge=1)
    # API_CONTRACT.md §11: 操作预览 30/min、操作提交 10/min（每用户）；
    # 提交还有设备互斥作为真实并发边界。
    operation_preview_rate_limit_per_minute: int = Field(default=30, ge=1)
    operation_submit_rate_limit_per_minute: int = Field(default=10, ge=1)
    # API_CONTRACT.md §11 launch：每用户每分钟可发起的远程连接请求数；真正的
    # 并发边界是 §7 的"每用户最多 3、每设备最多 1"活动票据上限
    # （application/launches.py 活动票据计数 + 事务级 advisory lock）。
    launch_rate_limit_per_minute: int = Field(default=10, ge=1)

    # Database
    postgres_dsn_file: Path | None = Field(default=None)
    postgres_dsn: str = Field(default="")

    # Secret files (read-only mounted secrets)
    credential_master_key_file: Path | None = Field(default=None)
    file_master_key_file: Path | None = Field(default=None)
    session_secret_file: Path | None = Field(default=None)
    csrf_secret_file: Path | None = Field(default=None)

    # Device network policy
    allowed_device_cidrs: str = Field(default="")

    # Collection / retention / worker pools (deployment configuration, not a product page)
    reachability_interval_seconds: int = Field(default=30, ge=5)
    metrics_interval_seconds: int = Field(default=60, ge=10)
    logs_interval_seconds: int = Field(default=120, ge=10)
    discovery_interval_seconds: int = Field(default=21600, ge=300)
    collection_workers: int = Field(default=4, ge=1, le=32)
    operation_workers: int = Field(default=2, ge=1, le=8)
    task_lease_seconds: int = Field(default=300, ge=30)
    # Worker execution tuning (M2T6): total attempts allowed for a read-only
    # operation task across crash-driven recovery requeues (the initial run
    # counts as attempt 1); the vendor-job poll cadence while a task sits in
    # waiting_device; and the progress-persistence throttle inside a single
    # adapter execute call. Deployment configuration, not product pages.
    operation_read_max_attempts: int = Field(default=2, ge=1, le=10)
    operation_job_poll_interval_seconds: float = Field(default=2.0, ge=0.05, le=300.0)
    operation_progress_min_interval_seconds: float = Field(default=1.0, ge=0.05, le=60.0)
    # SSE stream tuning (API_CONTRACT.md §10): poll cadence for ui_events and
    # keepalive comment cadence. Correctness never depends on NOTIFY
    # (ARCHITECTURE.md §5.3, ADR-024).
    sse_poll_interval_seconds: float = Field(default=1.0, ge=0.05, le=30.0)
    sse_keepalive_seconds: float = Field(default=15.0, ge=1, le=300)
    raw_retention_days: int = Field(default=7, ge=1)
    rollup_5m_retention_days: int = Field(default=30, ge=2)
    rollup_1h_retention_days: int = Field(default=180, ge=7)
    event_retention_days: int = Field(default=180, ge=7)
    resolved_alert_retention_days: int = Field(default=180, ge=7)
    operation_retention_days: int = Field(default=365, ge=30)
    audit_retention_days: int = Field(default=365, ge=30)
    support_bundle_retention_days: int = Field(default=30, ge=1)
    config_backup_keep_per_device: int = Field(default=10, ge=1)
    config_backup_min_days: int = Field(default=90, ge=1)

    # File quotas (deployment may lower, never raise without capacity evidence)
    max_support_bundle_bytes: int = Field(default=5 * 1024**3)
    max_firmware_bytes: int = Field(default=10 * 1024**3)
    max_virtual_media_bytes: int = Field(default=50 * 1024**3)

    # Controlled file store root (docs/ARCHITECTURE.md §3.6, SECURITY.md §9):
    # dev/test default lives under the repo (gitignored .warden-data);
    # production mounts a persistent volume and sets WARDEN_FILE_STORE_ROOT.
    file_store_root: Path = Field(default=Path(".warden-data/files"))

    # Ingress listeners (event-ingest)
    syslog_udp_port: int = Field(default=1514, ge=1, le=65535)
    syslog_tcp_port: int = Field(default=1514, ge=1, le=65535)
    snmp_trap_port: int = Field(default=1162, ge=1, le=65535)
    # The ingest listener must accept traps from the LAN; bind-all is the deployment default,
    # operators narrow it via WARDEN_INGEST_BIND_HOST behind the firewall.
    ingest_bind_host: str = Field(default="0.0.0.0")  # noqa: S104
    # The trap receiver ADDRESS the platform hands to devices through
    # snmp.configure (NAS-ACT-06): host:port as the DSM must reach it.
    # Deployment configuration ONLY — the operation profile prohibits
    # user-supplied receiver addresses; empty = snmp.configure preflight
    # fails not_configured.
    snmp_trap_receiver_address: str = Field(default="")

    # Platform base URL devices use to pull firmware / virtual media
    device_access_base_url: str = Field(default="")

    # Bootstrap
    bootstrap_admin_username: str = Field(default="")

    @field_validator("public_url", "device_access_base_url")
    @classmethod
    def _url_scheme(cls, value: str) -> str:
        if value and not value.startswith(("http://", "https://")):
            msg = "URL must start with http:// or https://"
            raise ValueError(msg)
        return value

    def secret_value(self, file: Path | None, fallback: str = "") -> str:
        if file is not None:
            raw = file.read_text(encoding="utf-8").strip()
            if not raw:
                msg = f"Secret file is empty: {file}"
                raise ValueError(msg)
            return raw
        return fallback

    @property
    def database_url(self) -> str:
        if self.postgres_dsn_file is not None:
            return self.secret_value(self.postgres_dsn_file)
        if not self.postgres_dsn:
            msg = "WARDEN_POSTGRES_DSN or WARDEN_POSTGRES_DSN_FILE must be configured"
            raise ValueError(msg)
        return self.postgres_dsn

    @property
    def credential_master_key(self) -> SecretStr:
        return SecretStr(self.secret_value(self.credential_master_key_file))

    @property
    def file_master_key(self) -> SecretStr:
        return SecretStr(self.secret_value(self.file_master_key_file))

    @property
    def session_secret(self) -> SecretStr:
        return SecretStr(self.secret_value(self.session_secret_file))

    @property
    def csrf_secret(self) -> SecretStr:
        return SecretStr(self.secret_value(self.csrf_secret_file))

    @property
    def allowed_device_networks(self) -> list[str]:
        return [item.strip() for item in self.allowed_device_cidrs.split(",") if item.strip()]

    @property
    def resolved_file_store_root(self) -> Path:
        """Absolute file-store root: relative values anchor at the repo root.

        Dev/test default ``.warden-data/files`` must land in the repo's
        gitignored data directory no matter the working directory (alembic,
        pytest and uvicorn all run from backend/); production sets an
        absolute volume path.
        """
        if self.file_store_root.is_absolute():
            return self.file_store_root
        return _REPO_ROOT / self.file_store_root

    @property
    def session_cookie_secure(self) -> bool:
        """Secure cookies everywhere except localhost development (SECURITY.md §2)."""
        host = urlparse(self.public_url).hostname or ""
        return not (self.app_env == "development" and host in {"localhost", "127.0.0.1"})


_WardenSettings = Annotated[WardenSettings, WardenSettings]


@lru_cache(maxsize=1)
def get_settings() -> WardenSettings:
    return WardenSettings()
