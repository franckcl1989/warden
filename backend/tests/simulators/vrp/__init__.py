"""VRP SSH test-device simulator package (M5T3).

A stateful Huawei-VRP CLI + SFTP simulator served over REAL asyncssh
(127.0.0.1, OS-assigned port, per-boot host key). It is a TEST DEVICE
SIMULATOR — never hardware evidence (README.md in this package). The CLI
surface, prompts, banners and every command behavior are the ``[sim]`` DSL
declared in ``device.py``/README.md; the adapter templates reference the same
DSL verbatim, so the executor tests prove real SSH transport mechanics while
the command semantics stay honestly simulator-declared (ADR-018) until M5
hardware certification records per-model/VRP CLI evidence.
"""
