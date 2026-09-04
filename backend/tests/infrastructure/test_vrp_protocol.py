"""VRP protocol tests: templates + parser (pure) and the asyncssh CLI
executor + SFTP against the REAL VRP simulator (M5T3).

Covers the binding rules with evidence:

- NO free-text commands: every executor call takes a template key + typed
  params; the injection suite proves params containing ``& ; | ` ] $ ( )``
  newlines or whitespace are rejected BEFORE composition;
- host-key pinning: automation refuses unpinned hosts; wrong fingerprints
  and wrong passwords fail with the stable codes; the interactive capture
  path (accept_unpinned) returns the actual fingerprint;
- paging disabled at session start; the ``-- More --`` marker never appears
  on big outputs; error markers map to the right codes;
- reboot flow: continue-prompt answered, save-prompt NEVER answered (abort),
  session close + blip semantics; SFTP flash writes + dir/startup readbacks.

The simulator is a TEST DEVICE SIMULATOR — never hardware evidence.
"""

from __future__ import annotations

import asyncio
import json
import re

import pytest
from app.infrastructure.protocols.vrp import (
    PromptAction,
    VrpError,
    VrpSshConfig,
    canonical_fingerprint,
    config_fingerprint,
    parse_compare_configuration,
    parse_dir_free_kb,
    parse_interface_state,
    parse_poe_state,
    parse_startup,
    parse_version,
    template_evidence_for,
    template_for,
    vrp_major_version,
)
from app.infrastructure.protocols.vrp.executor import (
    REBOOTED_MARKER,
    open_cli_executor,
)

from tests.simulators.vrp.device import SSH_PASSWORD, SSH_USERNAME
from tests.simulators.vrp.hosting import running_vrp_server

pytestmark = [
    pytest.mark.filterwarnings("ignore::pytest.PytestUnraisableExceptionWarning"),
    pytest.mark.filterwarnings("ignore::ResourceWarning"),
]

SAVE_PROMPT_RE = re.compile(r"Save it now\? \[Y/N\]:\s*$")
CONTINUE_REBOOT_RE = re.compile(r"Continue\? \[Y/N\]:\s*$")


def _config(handle, *, fingerprint: str | None = None, password: str = SSH_PASSWORD) -> VrpSshConfig:
    return VrpSshConfig(
        host="127.0.0.1",
        port=handle.port,
        username=SSH_USERNAME,
        password=password,
        fingerprint=(
            canonical_fingerprint(handle.host_fingerprint)
            if fingerprint is None
            else canonical_fingerprint(fingerprint)
        ),
    )


def _run(coro) -> object:
    return asyncio.run(coro)


@pytest.fixture()
def vrp_core():
    with running_vrp_server("core_s5732") as handle:
        yield handle


@pytest.fixture()
def vrp_access():
    with running_vrp_server("access_s5735") as handle:
        yield handle


# ---------------------------------------------------------------------------
# template registry: typed params + CLI injection defense


class TestTemplateInjectionDefense:
    """Params are allowlist-validated BEFORE any command composition.

    Every hostile value below would break the command line if interpolated
    (``& ; | ` ] $ ( )`` newlines, whitespace); ``compose`` must raise
    ValueError and never format the step with the raw value."""

    HOSTILE_VALUES = (
        "GigabitEthernet0/0/1&shutdown",
        "GigabitEthernet0/0/1;reboot",
        "GigabitEthernet0/0/1|more",
        "GigabitEthernet0/0/1`id`",
        "GigabitEthernet0/0/1]",
        "GigabitEthernet0/0/1$(reboot)",
        "GigabitEthernet0/0/1\nreboot",
        "GigabitEthernet0/0/1 reboot",
        "../GigabitEthernet0/0/1",
        "GigabitEthernet0/0/1\x1b[2J",
        "",
    )

    @pytest.mark.parametrize("value", HOSTILE_VALUES)
    def test_hostile_interface_id_rejected_before_composition(self, value: str) -> None:
        template = template_for("interface.shutdown")
        with pytest.raises(ValueError):
            template.compose({"interface_id": value})

    @pytest.mark.parametrize(
        "value",
        (
            "vrpcfg.cfg&reboot",
            "vrpcfg.cfg;reboot",
            "vrpcfg.cfg`ls`",
            "vrpcfg.cfg]",
            "warden-restore-00000000.cfg\nreboot",
            "warden-restore-00000000.cfg ",
            "../warden-restore-00000000.cfg",
            "warden-restore-0000000.cfg",  # too short hex
            "warden-restore-zzzzzzzz.cfg",  # non-hex
            "firmware-x.bin;rm",
            "",
        ),
    )
    def test_hostile_file_name_rejected(self, value: str) -> None:
        template = template_for("startup.system_software")
        with pytest.raises(ValueError):
            template.compose({"file_name": value})

    def test_valid_values_compose_exact_dsl_lines(self) -> None:
        template = template_for("interface.shutdown")
        steps = template.compose({"interface_id": "GigabitEthernet0/0/1"})
        assert steps == ("system-view", "interface GigabitEthernet0/0/1", "shutdown")
        eth = template_for("startup.saved_configuration").compose(
            {"file_name": "warden-restore-01234567.cfg"}
        )
        assert eth == ("startup saved-configuration warden-restore-01234567.cfg",)
        trunk = template_for("interface.shutdown").compose({"interface_id": "Eth-Trunk1"})
        assert trunk[-2] == "interface Eth-Trunk1"
        xge = template_for("display.interface").compose(
            {"interface_id": "XGigabitEthernet0/0/4"}
        )
        assert xge == ("display interface XGigabitEthernet0/0/4",)

    def test_unknown_and_missing_params_rejected(self) -> None:
        template = template_for("interface.shutdown")
        with pytest.raises(ValueError):
            template.compose({"interface_id": "GigabitEthernet0/0/1", "extra": "x"})
        with pytest.raises(ValueError):
            template.compose({})
        with pytest.raises(ValueError):
            template.compose({"interface_id": "GigabitEthernet0/0/1" * 20})  # too long

    def test_every_template_is_basis_tagged_and_static_or_paramtyped(self) -> None:
        from app.infrastructure.protocols.vrp.templates import TEMPLATES

        assert TEMPLATES
        for key, template in TEMPLATES.items():
            assert "[sim]" in template.basis, key
            assert template.template_version.startswith("vrp-cli-sim-"), key
            assert template.mode in ("user", "config", "interface"), key
            for step in template.steps:
                if step.startswith("system-view"):
                    assert template.mode in ("config", "interface"), key
            # no stray placeholders beyond the declared params
            for param in template.params:
                assert "{" + param.name + "}" in " ".join(template.steps), key

    def test_evidence_string_is_traceable(self) -> None:
        evidence = template_evidence_for("interface.shutdown")
        assert evidence.startswith("vrp-cli-sim-1:interface.shutdown")
        assert "[sim]" in evidence


# ---------------------------------------------------------------------------
# parser unit tests ([sim] DSL shapes)


class TestParser:
    def test_parse_version_output(self) -> None:
        parsed = parse_version(
            "Huawei Versatile Routing Platform Software\n"
            "VRP (R) software, Version V200R021C10SPC600 (S5732-H48XUM2CC V200R021C10SPC600)\n"
            "Device serial number : SIM-S5732-0001\n"
            "System uptime is 4321 seconds\n"
        )
        assert parsed["model"] == "S5732-H48XUM2CC"
        assert parsed["vrp_version"] == "V200R021C10SPC600"
        assert parsed["serial"] == "SIM-S5732-0001"
        assert parsed["uptime_seconds"] == 4321

    def test_parse_version_returns_none_for_missing_parts(self) -> None:
        parsed = parse_version("garbage\n")
        assert parsed["model"] is None
        assert parsed["vrp_version"] is None
        assert parsed["uptime_seconds"] is None

    def test_parse_interface_three_forms(self) -> None:
        up = parse_interface_state("GigabitEthernet0/0/1 current state : up\nLine protocol current state : up\n")
        assert (up["admin"], up["oper"]) == ("up", "up")
        down = parse_interface_state("GigabitEthernet0/0/1 current state : down\nLine protocol current state : down\n")
        assert (down["admin"], down["oper"]) == ("up", "down")
        admin = parse_interface_state(
            "GigabitEthernet0/0/1 current state : Administratively down\nLine protocol current state : down\n"
        )
        assert (admin["admin"], admin["oper"]) == ("down", "down")
        garbage = parse_interface_state("no state line here")
        assert garbage["found"] is False

    def test_parse_poe_and_compare_and_dir_and_startup(self) -> None:
        assert parse_poe_state("Port : GigabitEthernet0/0/1\nPower state : on\n") == "on"
        assert parse_poe_state("Power state : OFF") == "off"
        assert parse_poe_state("nothing") is None
        assert parse_compare_configuration(
            "Warning: The current configuration is different from the saved configuration (not saved)."
        ) is True
        assert parse_compare_configuration(
            "Info: The current configuration is the same as the saved configuration."
        ) is False
        assert parse_compare_configuration("weird") is None
        assert parse_dir_free_kb("Directory of flash:\nTotal 65536 KB (65000 KB free)\n") == 65000
        assert parse_dir_free_kb("nothing") is None
        startup = parse_startup(
            "System software    : firmware-V200R021C10SPC610.bin\n"
            "Startup saved-configuration file : warden-restore-01234567.cfg\n"
        )
        assert startup["boot_image"] == "firmware-V200R021C10SPC610.bin"
        assert startup["startup_file"] == "warden-restore-01234567.cfg"

    def test_config_fingerprint_normalization_is_deterministic(self) -> None:
        a = config_fingerprint("#\nsysname sim-s5732\r\n#\nreturn\r\n")
        b = config_fingerprint("#\nsysname sim-s5732\n#\nreturn\n")
        assert a == b
        assert config_fingerprint("#\nsysname sim-s5732\n#\nreturn\n") == b
        assert vrp_major_version("V200R021C10SPC600") == "V200R021C10"
        assert vrp_major_version("8.180") is None  # unknown naming -> no guess


# ---------------------------------------------------------------------------
# executor against the real simulator


class TestExecutorConnectivity:
    def test_pinned_fingerprint_connects_and_version_readback(self, vrp_core) -> None:
        async def scenario() -> None:
            executor = await open_cli_executor(_config(vrp_core))
            try:
                result = await executor.run_template("display.version", {})
                assert result.completed and not result.closed
                parsed = parse_version(result.text)
                assert parsed["model"] == "S5732-H48XUM2CC"
                assert parsed["vrp_version"] == "V200R021C10SPC600"
                assert parsed["serial"] == "SIM-S5732-0001"
            finally:
                await executor.close()

        _run(scenario())

    def test_wrong_fingerprint_is_host_key_mismatch(self, vrp_core) -> None:
        async def scenario() -> None:
            bad = _config(vrp_core, fingerprint="SHA256:" + "A" * 43)
            with pytest.raises(VrpError) as raised:
                await open_cli_executor(bad)
            assert raised.value.code == "validation_failed"
            assert "host_key_mismatch" in raised.value.message
            assert "host_key_mismatch" in raised.value.message

        _run(scenario())

    def test_wrong_password_is_authentication_failed(self, vrp_core) -> None:
        async def scenario() -> None:
            with pytest.raises(VrpError) as raised:
                await open_cli_executor(_config(vrp_core, password="wrong"))
            assert raised.value.code == "authentication_failed"

        _run(scenario())

    def test_unpinned_refused_for_automation_but_captured_interactively(
        self, vrp_core,
    ) -> None:
        async def scenario() -> None:
            unpinned = VrpSshConfig(
                host="127.0.0.1",
                port=vrp_core.port,
                username=SSH_USERNAME,
                password=SSH_PASSWORD,
                fingerprint=None,
            )
            with pytest.raises(VrpError) as refused:
                await open_cli_executor(unpinned)
            assert refused.value.code == "validation_failed"
            assert "首次信任" in refused.value.message
            # Interactive capture: accept_unpinned records the actual key.
            from app.infrastructure.protocols.vrp.session import open_connection

            conn, hook = await open_connection(unpinned, accept_unpinned=True)
            try:
                expected = canonical_fingerprint(vrp_core.host_fingerprint)
                assert hook.actual_fingerprint == expected
            finally:
                conn.close()
                await conn.wait_closed()

        _run(scenario())


class TestExecutorCommands:
    def test_interface_shutdown_readback_and_dirty(self, vrp_core) -> None:
        async def scenario() -> None:
            executor = await open_cli_executor(_config(vrp_core))
            try:
                await executor.run_template(
                    "interface.shutdown", {"interface_id": "GigabitEthernet0/0/2"}
                )
                result = await executor.run_template(
                    "display.interface", {"interface_id": "GigabitEthernet0/0/2"}
                )
                state = parse_interface_state(result.text)
                assert state["admin"] == "down"
                compare = await executor.run_template("compare.configuration", {})
                assert parse_compare_configuration(compare.text) is True
                # undo returns the port to up.
                await executor.run_template(
                    "interface.undo_shutdown", {"interface_id": "GigabitEthernet0/0/2"}
                )
                result = await executor.run_template(
                    "display.interface", {"interface_id": "GigabitEthernet0/0/2"}
                )
                assert parse_interface_state(result.text)["admin"] == "up"
            finally:
                await executor.close()

        _run(scenario())

    def test_unknown_interface_is_validation_failed(self, vrp_core) -> None:
        async def scenario() -> None:
            executor = await open_cli_executor(_config(vrp_core))
            try:
                with pytest.raises(VrpError) as raised:
                    await executor.run_template(
                        "display.interface", {"interface_id": "GigabitEthernet0/0/99"}
                    )
                assert raised.value.code == "validation_failed"
                assert "Wrong parameter" in raised.value.message
            finally:
                await executor.close()

        _run(scenario())

    def test_error_knob_maps_to_operation_failed(self, vrp_core) -> None:
        async def scenario() -> None:
            vrp_core.device.knobs.error_on_command = "display version"
            executor = await open_cli_executor(_config(vrp_core))
            try:
                with pytest.raises(VrpError) as raised:
                    await executor.run_template("display.version", {})
                assert raised.value.code == "operation_failed"
                assert "Simulated device failure" in raised.value.message
            finally:
                await executor.close()

        _run(scenario())

    def test_diagnostics_streams_without_paging(self, vrp_core) -> None:
        async def scenario() -> None:
            executor = await open_cli_executor(_config(vrp_core))
            try:
                result = await executor.run_template("display.diagnostic_information", {})
                assert result.completed
                assert "-- More --" not in result.text
                assert "End of diagnostic information" in result.text
                assert "Section fill line 60:" in result.text
            finally:
                await executor.close()

        _run(scenario())

    def test_config_text_and_fingerprint_stable(self, vrp_core) -> None:
        async def scenario() -> None:
            executor = await open_cli_executor(_config(vrp_core))
            try:
                first = await executor.run_template("display.current_configuration", {})
                assert first.completed
                fp1 = config_fingerprint(first.text)
                second = await executor.run_template("display.current_configuration", {})
                assert config_fingerprint(second.text) == fp1
            finally:
                await executor.close()

        _run(scenario())

    def test_poe_on_and_off_on_access_ports(self, vrp_access) -> None:
        async def scenario() -> None:
            executor = await open_cli_executor(_config(vrp_access))
            try:
                await executor.run_template("interface.poe_on", {"interface_id": "GigabitEthernet0/0/1"})
                result = await executor.run_template(
                    "display.poe", {"interface_id": "GigabitEthernet0/0/1"}
                )
                assert parse_poe_state(result.text) == "on"
                await executor.run_template("interface.poe_off", {"interface_id": "GigabitEthernet0/0/1"})
                result = await executor.run_template(
                    "display.poe", {"interface_id": "GigabitEthernet0/0/1"}
                )
                assert parse_poe_state(result.text) == "off"
                # XGE ports carry no PoE on the access profile.
                with pytest.raises(VrpError) as raised:
                    await executor.run_template(
                        "display.poe", {"interface_id": "XGigabitEthernet0/0/1"}
                    )
                assert raised.value.code == "operation_failed"
            finally:
                await executor.close()

        _run(scenario())


class TestExecutorReboot:
    def test_reboot_continue_and_close_with_blip(self, vrp_core) -> None:
        async def scenario() -> None:
            vrp_core.device.knobs.restart_blip_seconds = 0.7
            executor = await open_cli_executor(_config(vrp_core))
            try:
                interactions = (
                    PromptAction(pattern=CONTINUE_REBOOT_RE, reply="y"),
                )
                result = await executor.run_template("reboot", {}, interactions=interactions)
                assert result.closed and result.completed
                assert REBOOTED_MARKER in result.text
            finally:
                await executor.close()
            await asyncio.sleep(1.2)
            snapshot = vrp_core.device.snapshot()
            assert snapshot["uptime_seconds"] < 300

        _run(scenario())

    def test_save_prompt_is_never_answered(self, vrp_core) -> None:
        async def scenario() -> None:
            device = vrp_core.device
            device.knobs.save_prompt = True
            device.knobs.restart_blip_seconds = 0.3
            device.set_interface_admin("GigabitEthernet0/0/2", up=False)
            executor = await open_cli_executor(_config(vrp_core))
            try:
                interactions = (
                    PromptAction(
                        pattern=SAVE_PROMPT_RE,
                        abort=True,
                        abort_code="validation_failed",
                        abort_detail="检测到未保存配置提示（save prompt）；平台不自动保存，中止重启",
                    ),
                    PromptAction(pattern=CONTINUE_REBOOT_RE, reply="y"),
                )
                with pytest.raises(VrpError) as raised:
                    await executor.run_template("reboot", {}, interactions=interactions)
                assert raised.value.code == "validation_failed"
                assert "不自动保存" in raised.value.message
            finally:
                await executor.close()
            # The device never rebooted and stays dirty.
            snapshot = device.snapshot()
            assert snapshot["uptime_seconds"] >= 3600
            assert snapshot["dirty"] is True

        _run(scenario())


class TestExecutorSftpAndFirmware:
    def test_sftp_put_startup_software_reboot_version_bump(self, vrp_core) -> None:
        async def scenario() -> None:
            device = vrp_core.device
            device.knobs.restart_blip_seconds = 0.7
            image = (
                "WARDEN-SIM-FW "
                + json.dumps({"model": "S5732-H48XUM2CC", "version": "V200R021C10SPC610"})
                + "\npadding\n"
            ).encode("utf-8")
            executor = await open_cli_executor(_config(vrp_core))
            try:
                chunks = [image[index : index + 64] for index in range(0, len(image), 64)]
                await executor.sftp_put_bytes("firmware-V200R021C10SPC610.bin", chunks)
                # Space check via dir output (the platform flow's preflight).
                dir_result = await executor.run_template("dir.flash", {})
                assert parse_dir_free_kb(dir_result.text) is not None
                # Boot variable set.
                await executor.run_template(
                    "startup.system_software", {"file_name": "firmware-V200R021C10SPC610.bin"}
                )
                startup = await executor.run_template("display.startup", {})
                parsed = parse_startup(startup.text)
                assert parsed["boot_image"] == "firmware-V200R021C10SPC610.bin"
                # Reboot and read the version back.
                result = await executor.run_template(
                    "reboot", {}, interactions=(PromptAction(pattern=CONTINUE_REBOOT_RE, reply="y"),)
                )
                assert result.closed and result.completed
            finally:
                await executor.close()
            await asyncio.sleep(1.2)
            assert device.version == "V200R021C10SPC610"
            again = await open_cli_executor(_config(vrp_core))
            try:
                result = await again.run_template("display.version", {})
                assert parse_version(result.text)["vrp_version"] == "V200R021C10SPC610"
            finally:
                await again.close()

        _run(scenario())

    def test_sftp_rejects_names_outside_the_platform_allowlist(self, vrp_core) -> None:
        async def scenario() -> None:
            executor = await open_cli_executor(_config(vrp_core))
            try:
                with pytest.raises(VrpError) as raised:
                    await executor.sftp_put_bytes("evil.cfg;rm", [b"x"])
                assert raised.value.code == "validation_failed"
            finally:
                await executor.close()

        _run(scenario())

    def test_sftp_fail_knob_maps_to_operation_failed(self, vrp_core) -> None:
        async def scenario() -> None:
            device = vrp_core.device
            executor = await open_cli_executor(_config(vrp_core))
            try:
                device.knobs.sftp_fail = True
                with pytest.raises(VrpError) as raised:
                    await executor.sftp_put_bytes(
                        "warden-restore-01234567.cfg", [b"#\nsysname x\n"]
                    )
                assert raised.value.code == "operation_failed"
                device.knobs.sftp_fail = False
            finally:
                await executor.close()

        _run(scenario())
