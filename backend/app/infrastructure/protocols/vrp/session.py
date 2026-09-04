"""VRP SSH transport (asyncssh, M5T3) + sync-call facade.

Connection rules (DEVICE_ADAPTERS.md §6.1, SECURITY.md §8, M5T3 brief):

- automation commands ONLY over SSH (Telnet is never used for automation);
- host-key policy: a canonical SHA-256 host-key fingerprint
  (``ssh_host_fingerprint`` in the device connection config, captured by the
  onboarding flow) is ENFORCED at every connect — there is NO
  first-connect-trust for automation. Missing fingerprint -> the session
  refuses (``validation_failed``/``ssh_host_fingerprint_missing``) unless
  the interactive probe path explicitly passes ``accept_unpinned=True``,
  which reports the actual fingerprint (first-connect capture by an
  operator, never a silent accept for automation);
- fingerprint mismatch -> ``validation_failed`` with
  ``host_key_mismatch`` detail (decided + documented in the M5T3 report);
- credentials: password auth only in 0.1.0 (key auth is not in the secret
  schema — documented; the M5T2 secret schema declares username/password);
- timeouts: connect 10 s default (DEVICE_ADAPTERS.md §8), command
  timeouts live on the executor/templates.

Sync wrapper decision (documented): the asyncssh client is async while the
device-adapter methods (preflight/execute/verify) are sync worker calls —
the SAME pattern the M5T2 SNMP client uses: one ``asyncio.run`` per adapter
method call on the calling worker thread. Every adapter method therefore
opens ONE bounded SSH session for its whole flow (multi-command sequences
and read-backs share the connection; nothing spans two event loops).
"""

from __future__ import annotations

import asyncio
import contextlib
import re
from dataclasses import dataclass

import asyncssh
from asyncssh import SSHClient, SSHClientConnection, SSHKey, import_known_hosts

from app.infrastructure.protocols.vrp.errors import VrpError

#: canonical fingerprint form: ``SHA256:<base64>`` (asyncssh
#: ``get_fingerprint('sha256')`` output == the OpenSSH known_hosts form).
_FINGERPRINT_RE = re.compile(r"^(?:SHA256:)?([A-Za-z0-9+/]{43})=?$")

CONNECT_TIMEOUT_SECONDS = 10.0


def canonical_fingerprint(value: str) -> str:
    """Normalize an ``ssh_host_fingerprint`` config value.

    Accepts the OpenSSH ``SHA256:<base64>`` form and the bare base64;
    returns the canonical ``SHA256:<base64>`` form (asyncssh/OpenSSH).
    Raises ValueError for anything else.
    """
    match = _FINGERPRINT_RE.fullmatch(value.strip())
    if match is None:
        raise ValueError("SSH 主机指纹格式非法（期望 SHA256:<base64> 或裸 base64）")
    return f"SHA256:{match.group(1)}"


@dataclass(frozen=True)
class VrpSshConfig:
    """One automation SSH target (policy-resolved host/port from the device
    config; credentials are plaintext only inside the adapter call
    boundary, SECURITY.md §5)."""

    host: str
    port: int
    username: str
    password: str
    fingerprint: str | None = None  # canonical base64 or None (unpinned)


class _VerifyHostKey(SSHClient):
    """Client-side host-key gate.

    With an EMPTY known_hosts object asyncssh calls
    ``validate_host_public_key`` for every presented key (connection.py
    ``_validate_host_key``); this hook enforces the pinned fingerprint and
    records what the device actually presented (capture/mismatch detail).
    """

    def __init__(self, expected: str | None) -> None:
        self.expected = expected
        self.actual_fingerprint: str | None = None
        self.actual_key: SSHKey | None = None

    def validate_host_public_key(self, host: str, addr: str, port: int, key: SSHKey) -> bool:
        del host, addr, port
        self.actual_key = key
        self.actual_fingerprint = key.get_fingerprint("sha256")
        if self.expected is None:
            return True  # interactive first-connect only (probe capture)
        return self.actual_fingerprint == self.expected




async def open_connection(
    config: VrpSshConfig,
    *,
    accept_unpinned: bool = False,
    connect_timeout: float = CONNECT_TIMEOUT_SECONDS,
) -> tuple[SSHClientConnection, SSHClient | None]:
    """Open an authenticated SSH connection with the host-key policy.

    Returns (connection, client_hook). Raises ``VrpError`` with the stable
    codes of ``errors.py``; the hook carries ``actual_fingerprint`` for the
    probe's first-connect capture and mismatch detail.
    """
    if config.fingerprint is None and not accept_unpinned:
        raise VrpError(
            "validation_failed",
            "未固定 SSH 主机指纹（ssh_host_fingerprint）；自动化连接拒绝首次信任（host_key_missing）",
            stage="connect",
        )
    hook = _VerifyHostKey(config.fingerprint)
    # An EMPTY known_hosts object makes asyncssh call the validation hook for
    # every presented key — enforcement (pinned) and first-connect capture
    # (unpinned interactive probe) both run through the hook.
    known_hosts = (
        import_known_hosts("")
        if config.fingerprint is not None or accept_unpinned
        else None
    )
    try:
        conn = await asyncio.wait_for(
            asyncssh.connect(
                config.host,
                port=config.port,
                username=config.username,
                password=config.password,
                known_hosts=known_hosts,
                client_factory=lambda: hook,
            ),
            timeout=connect_timeout,
        )
    except TimeoutError as exc:
        raise VrpError(
            "network_unreachable", "SSH 连接超时（10 秒连接窗口）", stage="connect"
        ) from exc
    except asyncssh.PermissionDenied as exc:
        raise VrpError(
            "authentication_failed", "SSH 密码认证被设备拒绝", stage="connect"
        ) from exc
    except asyncssh.Error as exc:
        message = str(exc) or type(exc).__name__
        lowered = message.lower()
        if "host key" in lowered or "host_key" in lowered:
            actual = hook.actual_fingerprint
            detail = (
                f"SSH 主机指纹不匹配（host_key_mismatch）：期望 {config.fingerprint}，"
                f"设备实际 {actual if actual is not None else '未知'}"
            )
            raise VrpError("validation_failed", detail, stage="connect") from exc
        raise VrpError(
            "network_unreachable",
            f"SSH 连接失败：{message[:160]}（设备重启窗口/不可达）",
            stage="connect",
        ) from exc
    except OSError as exc:
        raise VrpError(
            "network_unreachable", f"SSH 网络不可达：{exc.strerror or str(exc)[:160]}", stage="connect"
        ) from exc
    return conn, hook


async def close_connection(conn: SSHClientConnection) -> None:
    conn.close()
    with contextlib.suppress(TimeoutError, asyncssh.Error):
        await asyncio.wait_for(conn.wait_closed(), timeout=5.0)
