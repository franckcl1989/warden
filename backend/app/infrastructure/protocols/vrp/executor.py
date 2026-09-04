"""VRP CLI executor: prompt-stack command flow over one SSH session.

The executor is the ONLY way the Huawei adapter ops send commands: it takes
a template KEY + typed params (never a raw command string from callers
outside the adapter — SECURITY.md §8), walks the view stack (user ->
system -> interface, ``return`` back to the user view), disables paging
once per session (``screen-length 0 temporary``), reads until the expected
prompt of each view, applies declared interactive prompt actions (reboot
continue/save prompts) and detects the ``Error:`` signatures of the [sim]
DSL. Timeouts: connect 10 s (session.py); commands bounded by the template
default or an explicit timeout; a read that expires raises
``VrpTimeoutError``; an unexpected paging marker (paging should be off)
or a session that stops behaving like the DSL raises ``protocol_error`` —
the executor never answers prompts it does not understand and never guesses
success.

``run_template`` returns once the session is back at the user-view prompt
(or the connection closed, e.g. an accepted reboot): the caller's read-back
(verify) then proves the outcome per the profile — never the command reply
alone.
"""

from __future__ import annotations

import asyncio
import re
import time
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from app.infrastructure.protocols.vrp.errors import VrpError, VrpTimeoutError
from app.infrastructure.protocols.vrp.parser import (
    clean_output,
    config_prompt_match,
    find_error_markers,
    user_prompt_match,
)
from app.infrastructure.protocols.vrp.session import VrpSshConfig
from app.infrastructure.protocols.vrp.templates import template_evidence, template_for

#: paging marker of the [sim] DSL — must never appear with paging disabled.
MORE_MARKER = "-- More --"
REBOOTED_MARKER = "System is rebooting now"

#: how long the initial banner/prompt may take.
_BANNER_TIMEOUT_SECONDS = 15.0


@dataclass(frozen=True)
class PromptAction:
    """One interactive prompt the executor may legally answer.

    ``reply`` writes the answer and continues; ``abort=True`` stops the run
    with an explicit error (the executor NEVER answers a prompt it was not
    declared to handle — e.g. the unsaved-config save prompt on reboot).
    """

    pattern: re.Pattern[str]
    reply: str | None = None
    abort: bool = False
    abort_detail: str = "交互提示不应出现，已中止命令"
    abort_code: str = "operation_failed"


@dataclass(frozen=True)
class CommandResult:
    """Outcome of one template run.

    ``text`` is the cleaned output read between the first command line and
    the terminal state (the DSL has no echo). ``closed`` marks a session the
    device ended (an accepted reboot); ``completed`` is False when the
    stream ended before the expected prompt without a reboot marker.
    """

    template_key: str
    text: str
    completed: bool
    closed: bool = False
    markers: tuple[str, ...] = ()
    template_version: str = ""


class VrpCliExecutor:
    """Prompt-stack CLI state over one authenticated SSH session."""

    def __init__(self, conn: Any, process: Any) -> None:
        self._conn = conn
        self._process = process
        self._sysname: str | None = None
        self._buffer = ""
        self._eof = False
        self._started = False
        #: actual device host-key fingerprint seen at connect (first-connect
        #: capture / mismatch detail); None until a connect hook reports it.
        self.actual_fingerprint: str | None = None

    @property
    def sysname(self) -> str | None:
        return self._sysname

    # -- io ------------------------------------------------------------------

    async def _read_some(self, wait_seconds: float) -> None:
        """Append one chunk to the buffer (or set EOF)."""
        try:
            chunk = await asyncio.wait_for(
                self._process.stdout.read(65536), timeout=wait_seconds
            )
        except TimeoutError as exc:
            raise VrpTimeoutError("命令输出等待超时", stage="command") from exc
        if not chunk:
            self._eof = True
            return
        self._buffer += clean_output(str(chunk))

    async def _write(self, text: str) -> None:
        self._process.stdin.write(text)
        try:
            await asyncio.wait_for(self._process.stdin.drain(), timeout=10.0)
        except TimeoutError as exc:
            raise VrpTimeoutError("命令发送超时", stage="command") from exc

    async def _send_line(self, line: str) -> None:
        await self._write(line + "\n")

    def _raise_on_errors(self) -> None:
        """Fail fast on explicit ``Error:`` markers (device refusal)."""
        markers = find_error_markers(self._buffer)
        if not markers:
            return
        from app.infrastructure.protocols.vrp.parser import classify_error_marker

        first = markers[0]
        raise VrpError(
            classify_error_marker(first),
            f"设备返回命令错误：{first[:200]}",
            stage="command",
        )

    # -- session start ---------------------------------------------------------

    async def start(self) -> None:
        """Consume the banner up to the user-view prompt; disable paging."""
        if self._started:
            return
        deadline = time.monotonic() + _BANNER_TIMEOUT_SECONDS
        while user_prompt_match(self._buffer) is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise VrpError(
                    "protocol_error",
                    "SSH 会话未出现 VRP 用户视图提示符（banner 解析失败）",
                    stage="connect",
                )
            await self._read_some(min(remaining, 5.0))
            if self._eof:
                raise VrpError(
                    "protocol_error",
                    "SSH 会话在出现提示符前被设备关闭",
                    stage="connect",
                )
        sysname = user_prompt_match(self._buffer)
        assert sysname is not None
        self._sysname = sysname
        self._buffer = ""
        # Paging must be off for every automation read (DEVICE_ADAPTERS.md
        # §8 big-output commands); a device that does not honor the command
        # trips the MORE_MARKER guard instead of hanging the caller.
        await self.run_template("paging.off", {}, wait_seconds=30)
        self._started = True

    # -- core run ---------------------------------------------------------------

    async def run_template(
        self,
        key: str,
        params: dict[str, str],
        *,
        wait_seconds: int | None = None,
        interactions: tuple[PromptAction, ...] = (),
    ) -> CommandResult:
        """Run one certified template with typed params.

        The session returns to the user view before and after the run (a
        config/interface run issues ``return`` at its end). Each step reads
        until its view prompt; error markers fail fast; declared interactive
        prompts are answered (reply) or abort the run; ``-- More --`` with
        paging disabled is a protocol error. A closed stream carrying the
        reboot marker is a completed reboot (``closed=True``).
        """
        template = template_for(key)
        steps = template.compose(params)
        if wait_seconds is None:
            wait_seconds = template.timeout_seconds
        deadline = time.monotonic() + wait_seconds
        await self._ensure_user_view(deadline)

        text = ""
        for step in steps:
            view = self._step_view(template.mode, step)
            await self._send_line(step)
            text += await self._read_until_view(view, deadline, interactions=interactions)
            if self._eof:
                break
        if self._eof:
            if REBOOTED_MARKER in text:
                return CommandResult(
                    template_key=key,
                    text=text,
                    completed=True,
                    closed=True,
                    template_version=template.template_version,
                )
            return CommandResult(
                template_key=key,
                text=text,
                completed=False,
                closed=True,
                template_version=template.template_version,
            )
        if template.mode in ("config", "interface"):
            await self._send_line("return")
            text += await self._read_until_view("user", deadline, interactions=interactions)
        return CommandResult(
            template_key=key,
            text=text,
            completed=True,
            closed=False,
            markers=find_error_markers(text),
            template_version=template.template_version,
        )

    @staticmethod
    def _step_view(mode: str, step: str) -> str:
        """The view whose prompt terminates ONE step of a template.

        A user-mode template runs at the user view. A config-mode template
        first enters the system view (``system-view`` ends at the config
        prompt) and runs its steps at the config prompt. An interface-mode
        template enters system view, selects the interface (ends at the
        interface prompt) and runs its steps there.
        """
        if step == "system-view":
            return "config"
        if step.startswith("interface "):
            return "interface"
        return mode if mode in ("config", "interface") else "user"

    # -- prompt-walking ---------------------------------------------------------

    async def _ensure_user_view(self, deadline: float) -> None:
        """Return to the user view when a previous run left a deeper view."""
        if user_prompt_match(self._buffer) is not None:
            self._buffer = ""
            return
        await self._send_line("return")
        while user_prompt_match(self._buffer) is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise VrpTimeoutError("返回用户视图超时", stage="command")
            await self._read_some(remaining)
            if self._eof:
                raise VrpError(
                    "protocol_error", "会话在返回用户视图前被设备关闭", stage="command"
                )
        sysname = user_prompt_match(self._buffer)
        assert sysname is not None
        self._sysname = sysname
        self._buffer = ""

    async def _read_until_view(
        self,
        view: str,
        deadline: float,
        *,
        interactions: tuple[PromptAction, ...],
    ) -> str:
        """Read until the expected view prompt (or EOF), returning the text.

        Interactive prompt handling: when a declared interaction matches the
        buffer, the prompt text is consumed and answered (reply) or the run
        aborts with an explicit VrpError. Undeclared prompts simply do not
        match a view and the read continues until the timeout — the
        executor never guesses what a foreign prompt wants.
        """
        accumulated = ""
        while True:
            # Fail fast on explicit device refusals BEFORE any success
            # interpretation (an error reply may carry the prompt too).
            self._raise_on_errors()
            if self._at_view(view):
                accumulated += self._buffer
                self._buffer = ""
                return accumulated
            if self._eof:
                accumulated += self._buffer
                self._buffer = ""
                return accumulated
            if MORE_MARKER in self._buffer:
                raise VrpError(
                    "protocol_error",
                    "出现分页提示（-- More --）而分页已被禁用（screen-length 未生效），中止读取",
                    stage="command",
                )
            action = self._match_interaction(interactions)
            if action is not None:
                consumed, prompt_action = action
                accumulated += consumed
                if prompt_action.abort:
                    raise VrpError(
                        prompt_action.abort_code,
                        prompt_action.abort_detail,
                        stage="command",
                    )
                if prompt_action.reply is not None:
                    await self._send_line(prompt_action.reply)
                continue
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise VrpTimeoutError(
                    f"等待 {view} 视图提示符超时（命令未在时限内完成）", stage="command"
                )
            await self._read_some(remaining)

    def _at_view(self, view: str) -> bool:
        if view == "user":
            return user_prompt_match(self._buffer) is not None
        match = config_prompt_match(self._buffer, self._sysname)
        if match is None:
            return False
        sysname, iface = match
        if sysname != self._sysname:
            return False
        if view == "config":
            return iface is None
        return iface is not None

    def _match_interaction(
        self, interactions: tuple[PromptAction, ...]
    ) -> tuple[str, PromptAction] | None:
        for prompt_action in interactions:
            match = prompt_action.pattern.search(self._buffer)
            if match is not None:
                consumed = self._buffer[: match.end()]
                self._buffer = self._buffer[match.end() :]
                return consumed, prompt_action
        return None

    # -- session end -------------------------------------------------------------

    async def sftp_put_bytes(
        self,
        name: str,
        data_chunks: Iterable[bytes],
        *,
        wait_seconds: float = 120.0,
    ) -> None:
        """Stream ``data_chunks`` (iterable of bytes) into the device flash
        over the SFTP subsystem of THIS session (bounded by ``wait_seconds``).

        The file name must already satisfy the platform naming allowlist
        (``warden-restore-<hex8>.cfg`` / ``firmware-<slug>.bin``) — SFTP
        transfers are DATA, never command text, so no CLI interpolation is
        involved (the injection defense documented in the templates)."""
        import asyncssh

        from app.infrastructure.protocols.vrp.templates import _FILE_NAME_RE

        if _FILE_NAME_RE.fullmatch(name) is None:
            raise VrpError(
                "validation_failed",
                f"SFTP 文件名 {name!r} 不在平台命名白名单内，拒绝传输",
                stage="command",
            )
        try:
            sftp = await asyncio.wait_for(
                self._conn.start_sftp_client(), timeout=min(wait_seconds, 30.0)
            )
        except TimeoutError as exc:
            raise VrpTimeoutError("SFTP 通道建立超时", stage="command") from exc
        try:
            try:
                handle = await asyncio.wait_for(
                    sftp.open(name, "wb"), timeout=min(wait_seconds, 30.0)
                )
            except asyncssh.Error as exc:
                raise VrpError(
                    "operation_failed",
                    f"设备拒绝写入 {name!r}（{str(exc)[:160]}）",
                    stage="command",
                ) from exc
            try:
                started = time.monotonic()
                for chunk in data_chunks:
                    remaining = wait_seconds - (time.monotonic() - started)
                    if remaining <= 0:
                        raise VrpTimeoutError("SFTP 传输超时", stage="command")
                    try:
                        await asyncio.wait_for(handle.write(chunk), timeout=remaining)
                    except TimeoutError as exc:
                        raise VrpTimeoutError("SFTP 传输超时", stage="command") from exc
            finally:
                await handle.close()
        finally:
            sftp.exit()

    async def close(self) -> None:
        from app.infrastructure.protocols.vrp.session import close_connection

        await close_connection(self._conn)


def template_evidence_for(key: str) -> str:
    """Evidence string (template version + [sim] basis) for operations."""
    return template_evidence(key)


async def open_cli_executor(
    config: VrpSshConfig,
    *,
    accept_unpinned: bool = False,
    connect_wait_seconds: float = 10.0,
) -> VrpCliExecutor:
    """Open an authenticated session and start a CLI executor on it.

    The caller owns the returned executor and must ``await close()`` it
    (also closes the underlying connection). One executor == one SSH
    session == one adapter method call (sync wrapper decision, session.py).
    """
    from app.infrastructure.protocols.vrp.session import open_connection

    conn, hook = await open_connection(
        config,
        accept_unpinned=accept_unpinned,
        connect_timeout=connect_wait_seconds,
    )
    try:
        process = await asyncio.wait_for(
            conn.create_process(term_type="xterm"), timeout=connect_wait_seconds
        )
    except (TimeoutError, Exception) as exc:  # noqa: BLE001
        conn.close()
        raise VrpError("network_unreachable", f"SSH 会话建立失败：{exc}", stage="connect") from exc
    executor = VrpCliExecutor(conn, process)
    executor.actual_fingerprint = getattr(hook, "actual_fingerprint", None)
    try:
        await executor.start()
    except BaseException:
        await executor.close()
        raise
    return executor
