"""Unit tests for the dynamic analysis module (frida-free, mock-based).

Device and lldb probes are exercised by stubbing ``run_command``, the single
seam every external-tool call now goes through, rather than by patching
``subprocess.run`` globally.
"""

from __future__ import annotations

import importlib
import json
import sys
from unittest.mock import patch

import pytest

from shingan.core.models import Finding, Severity
from shingan.core.shell import CommandResult


def _ok(stdout: str) -> CommandResult:
    return CommandResult(returncode=0, stdout=stdout, stderr="")


def _failed(stderr: str = "", returncode: int = 1) -> CommandResult:
    return CommandResult(returncode=returncode, stdout="", stderr=stderr)


@pytest.fixture
def dynamic_finding():
    def _make(outcome: str, rule_id: str = "IOS-DYN-001") -> Finding:
        return Finding(
            rule_id=rule_id,
            title="test",
            severity=Severity.HIGH if outcome == "bypassed" else Severity.INFO,
            description="",
            extra={"source": "dynamic", "outcome": outcome},
        )

    return _make


# ── runner: unavailable when frida is missing ─────────────────────────────────


def _reload_runner():
    import shingan.core.dynamic.runner as runner_mod

    importlib.reload(runner_mod)
    return runner_mod


def test_runner_returns_unavailable_without_frida() -> None:
    with patch.dict(sys.modules, {"frida": None}):
        findings = _reload_runner().run_dynamic_checks("com.example.app")

    assert len(findings) == 3
    assert all(f.extra.get("outcome") == "unavailable" for f in findings)
    assert all(f.extra.get("source") == "dynamic" for f in findings)
    assert all(f.severity == Severity.INFO for f in findings)


def test_runner_unavailable_rule_ids() -> None:
    with patch.dict(sys.modules, {"frida": None}):
        findings = _reload_runner().run_dynamic_checks("com.example.app")

    assert {f.rule_id for f in findings} == {
        "IOS-DYN-001",
        "IOS-DYN-002",
        "IOS-DYN-003",
    }


def test_runner_android_unavailable_without_frida() -> None:
    with patch.dict(sys.modules, {"frida": None}):
        findings = _reload_runner().run_dynamic_checks(
            "com.example.app", platform="android"
        )

    assert len(findings) == 2
    assert {f.rule_id for f in findings} == {"AND-DYN-001", "AND-DYN-002"}
    assert all(f.extra.get("outcome") == "unavailable" for f in findings)


# ── ScanResult dynamic/static breakdown ───────────────────────────────────────


def test_summary_no_dynamic_findings(make_result, make_finding) -> None:
    result = make_result([make_finding("IOS-SYM-001", severity=Severity.HIGH)])
    summary = result.to_dict()["summary"]
    assert summary["dynamic"]["total"] == 0
    assert summary["dynamic"]["bypassed"] == 0
    assert summary["static"]["total"] == 1
    assert summary["static"]["high"] == 1


def test_summary_with_bypassed_finding(
    make_result, make_finding, dynamic_finding
) -> None:
    result = make_result(
        [
            make_finding("IOS-SYM-001", severity=Severity.HIGH),
            dynamic_finding("bypassed", "IOS-DYN-001"),
        ]
    )
    summary = result.to_dict()["summary"]
    assert summary["dynamic"]["bypassed"] == 1
    assert summary["dynamic"]["resistant"] == 0
    assert summary["dynamic"]["high"] == 1
    assert summary["static"]["high"] == 1
    assert summary["high"] == 2  # top-level total spans both sources
    assert summary["total"] == 2


def test_summary_with_resistant_finding(make_result, dynamic_finding) -> None:
    summary = make_result([dynamic_finding("resistant", "IOS-DYN-002")]).to_dict()[
        "summary"
    ]
    assert summary["dynamic"]["resistant"] == 1
    assert summary["dynamic"]["bypassed"] == 0
    assert summary["dynamic"]["info"] == 1


def test_summary_mixed_outcomes(make_result, dynamic_finding) -> None:
    result = make_result(
        [
            dynamic_finding("bypassed", "IOS-DYN-001"),
            dynamic_finding("resistant", "IOS-DYN-002"),
            dynamic_finding("unavailable", "IOS-DYN-003"),
        ]
    )
    summary = result.to_dict()["summary"]
    assert summary["dynamic"]["total"] == 3
    assert summary["dynamic"]["bypassed"] == 1
    assert summary["dynamic"]["resistant"] == 1
    assert summary["static"]["total"] == 0


def test_summary_backward_compatible_keys(
    make_result, make_finding, dynamic_finding
) -> None:
    result = make_result(
        [
            make_finding("A", severity=Severity.HIGH),
            make_finding("B", severity=Severity.MEDIUM),
            dynamic_finding("bypassed"),
        ]
    )
    s = result.to_dict()["summary"]
    assert s["high"] == 2  # 1 static + 1 dynamic bypassed (HIGH)
    assert s["medium"] == 1
    assert s["low"] == 0
    assert s["total"] == 3
    assert "suppressed" in s


# ── pt_deny_attach: lldb classification ───────────────────────────────────────

_LLDB_TARGET = "shingan.core.dynamic.checks.pt_deny_attach.run_command"


def test_pt_deny_attach_resistant_on_timeout() -> None:
    from shingan.core.dynamic.checks.pt_deny_attach import _attempt_lldb_attach

    timed_out = CommandResult(returncode=124, stdout="", stderr="", timed_out=True)
    with patch(_LLDB_TARGET, return_value=timed_out):
        result = _attempt_lldb_attach(pid=12345, timeout=15)

    assert result["outcome"] == "resistant"
    assert "timed out" in result["detail"]


def test_pt_deny_attach_unavailable_when_lldb_missing() -> None:
    from shingan.core.dynamic.checks.pt_deny_attach import _attempt_lldb_attach

    missing = CommandResult(returncode=127, stdout="", stderr="", missing=True)
    with patch(_LLDB_TARGET, return_value=missing):
        result = _attempt_lldb_attach(pid=12345)

    assert result["outcome"] == "unavailable"
    assert "lldb" in result["detail"]


def test_pt_deny_attach_bypassed_on_successful_attach() -> None:
    from shingan.core.dynamic.checks.pt_deny_attach import _attempt_lldb_attach

    attached = _ok("process attach stopped\nthread list ...")
    with patch(_LLDB_TARGET, return_value=attached):
        result = _attempt_lldb_attach(pid=12345)

    assert result["outcome"] == "bypassed"


def test_pt_deny_attach_resistant_on_permission_denied() -> None:
    from shingan.core.dynamic.checks.pt_deny_attach import _attempt_lldb_attach

    refused = _failed("error: attach failed — ptrace: Operation not permitted")
    with patch(_LLDB_TARGET, return_value=refused):
        result = _attempt_lldb_attach(pid=12345)

    assert result["outcome"] == "resistant"


def test_pt_deny_attach_error_on_unrecognised_output() -> None:
    from shingan.core.dynamic.checks.pt_deny_attach import _attempt_lldb_attach

    with patch(_LLDB_TARGET, return_value=_ok("something unexpected")):
        result = _attempt_lldb_attach(pid=12345)

    assert result["outcome"] == "error"


# ── device listing: xcrun simulators ──────────────────────────────────────────

_DEVICE_TARGET = "shingan.core.dynamic.device.run_command"


def test_list_simulators_returns_empty_on_xcrun_failure() -> None:
    from shingan.core.dynamic.device import _list_simulators_via_xcrun

    missing = CommandResult(returncode=127, stdout="", stderr="", missing=True)
    with patch(_DEVICE_TARGET, return_value=missing):
        assert _list_simulators_via_xcrun() == []


def test_list_simulators_parses_booted_only() -> None:
    from shingan.core.dynamic.device import _list_simulators_via_xcrun

    payload = json.dumps(
        {
            "devices": {
                "com.apple.CoreSimulator.SimRuntime.iOS-17-4": [
                    {"udid": "ABC-123", "name": "iPhone 15", "state": "Booted"},
                    {"udid": "DEF-456", "name": "iPhone 14", "state": "Shutdown"},
                ]
            }
        }
    )

    with patch(_DEVICE_TARGET, return_value=_ok(payload)):
        devices = _list_simulators_via_xcrun()

    assert len(devices) == 1
    assert devices[0].udid == "ABC-123"
    assert devices[0].kind == "simulator"
    assert devices[0].os_version == "iOS 17.4"


def test_list_simulators_handles_malformed_json() -> None:
    from shingan.core.dynamic.device import _list_simulators_via_xcrun

    with patch(_DEVICE_TARGET, return_value=_ok("{not json")):
        assert _list_simulators_via_xcrun() == []


# ── device listing: adb ───────────────────────────────────────────────────────

_ADB_OUTPUT = (
    "List of devices attached\n"
    "emulator-5554          device product:sdk_gphone_x86_64 "
    "model:sdk_gphone_x86_64 device:emu64xa\n"
    "192.168.1.10:5555      device product:taimen model:Pixel_2 device:taimen\n"
)


def test_list_emulators_via_adb_parses_emulator() -> None:
    from shingan.core.dynamic.device import _list_emulators_via_adb

    # First call lists devices; the two that follow are getprop lookups.
    responses = [_ok(_ADB_OUTPUT), _ok("10"), _ok("14")]
    with patch(_DEVICE_TARGET, side_effect=responses):
        devices = _list_emulators_via_adb()

    assert len(devices) == 2
    emu = next(d for d in devices if d.udid == "emulator-5554")
    assert emu.kind == "emulator"
    assert emu.os_version == "Android 10"
    assert emu.name == "sdk gphone x86 64"

    real = next(d for d in devices if d.udid == "192.168.1.10:5555")
    assert real.kind == "usb"


def test_list_emulators_returns_empty_on_adb_failure() -> None:
    from shingan.core.dynamic.device import _list_emulators_via_adb

    missing = CommandResult(returncode=127, stdout="", stderr="", missing=True)
    with patch(_DEVICE_TARGET, return_value=missing):
        assert _list_emulators_via_adb() == []


def test_list_emulators_skips_offline() -> None:
    from shingan.core.dynamic.device import _list_emulators_via_adb

    offline = _ok("List of devices attached\nemulator-5554          offline\n")
    with patch(_DEVICE_TARGET, return_value=offline):
        assert _list_emulators_via_adb() == []


def test_list_emulators_without_os_version() -> None:
    from shingan.core.dynamic.device import _list_emulators_via_adb

    responses = [_ok(_ADB_OUTPUT), _failed(), _failed()]
    with patch(_DEVICE_TARGET, side_effect=responses):
        devices = _list_emulators_via_adb()

    assert all(d.os_version == "Android" for d in devices)
