"""Unit tests for dynamic analysis module (frida-free, mock-based)."""

from __future__ import annotations

import sys
from unittest.mock import MagicMock, patch

from shingan.core.models import Finding, ScanResult, Severity


# ── Helpers ───────────────────────────────────────────────────────────────────


def _make_result(findings: list[Finding] | None = None) -> ScanResult:
    r = ScanResult(app_id="com.example", app_version="1.0", build="1", ipa_name="t.ipa")
    r.findings = findings or []
    return r


def _dynamic_finding(outcome: str, rule_id: str = "IOS-DYN-001") -> Finding:
    return Finding(
        rule_id=rule_id,
        title="test",
        severity=Severity.HIGH if outcome == "bypassed" else Severity.INFO,
        description="",
        extra={"source": "dynamic", "outcome": outcome},
    )


# ── runner: unavailable when frida missing ────────────────────────────────────


def test_runner_returns_unavailable_without_frida():
    """When frida is not installed, all findings have outcome=unavailable."""
    # Temporarily hide frida from the import system
    with patch.dict(sys.modules, {"frida": None}):
        # Re-import to pick up the patched sys.modules
        import importlib
        import shingan.core.dynamic.runner as runner_mod

        importlib.reload(runner_mod)

        findings = runner_mod.run_dynamic_checks("com.example.app")

    assert len(findings) == 3
    assert all(f.extra.get("outcome") == "unavailable" for f in findings)
    assert all(f.extra.get("source") == "dynamic" for f in findings)
    assert all(f.severity == Severity.INFO for f in findings)


def test_runner_unavailable_rule_ids():
    with patch.dict(sys.modules, {"frida": None}):
        import importlib
        import shingan.core.dynamic.runner as runner_mod

        importlib.reload(runner_mod)
        findings = runner_mod.run_dynamic_checks("com.example.app")

    rule_ids = {f.rule_id for f in findings}
    assert rule_ids == {"IOS-DYN-001", "IOS-DYN-002", "IOS-DYN-003"}


def test_runner_android_unavailable_without_frida():
    """Android platform returns AND-DYN-001/002 when frida is missing."""
    with patch.dict(sys.modules, {"frida": None}):
        import importlib
        import shingan.core.dynamic.runner as runner_mod

        importlib.reload(runner_mod)
        findings = runner_mod.run_dynamic_checks("com.example.app", platform="android")

    assert len(findings) == 2
    rule_ids = {f.rule_id for f in findings}
    assert rule_ids == {"AND-DYN-001", "AND-DYN-002"}
    assert all(f.extra.get("outcome") == "unavailable" for f in findings)
    assert all(f.severity == Severity.INFO for f in findings)


# ── ScanResult summary breakdown ──────────────────────────────────────────────


def test_summary_no_dynamic_findings():
    """Summary has empty dynamic section when no dynamic findings exist."""
    result = _make_result([Finding("IOS-SYM-001", "t", Severity.HIGH, "d")])
    d = result.to_dict()
    assert d["summary"]["dynamic"]["total"] == 0
    assert d["summary"]["dynamic"]["bypassed"] == 0
    assert d["summary"]["static"]["total"] == 1
    assert d["summary"]["static"]["high"] == 1


def test_summary_with_bypassed_finding():
    result = _make_result(
        [
            Finding("IOS-SYM-001", "t", Severity.HIGH, "d"),
            _dynamic_finding("bypassed", "IOS-DYN-001"),
        ]
    )
    d = result.to_dict()
    assert d["summary"]["dynamic"]["bypassed"] == 1
    assert d["summary"]["dynamic"]["resistant"] == 0
    assert d["summary"]["dynamic"]["high"] == 1
    assert d["summary"]["static"]["high"] == 1
    # Top-level total still works (backward compat)
    assert d["summary"]["high"] == 2
    assert d["summary"]["total"] == 2


def test_summary_with_resistant_finding():
    result = _make_result([_dynamic_finding("resistant", "IOS-DYN-002")])
    d = result.to_dict()
    assert d["summary"]["dynamic"]["resistant"] == 1
    assert d["summary"]["dynamic"]["bypassed"] == 0
    assert d["summary"]["dynamic"]["info"] == 1


def test_summary_mixed_outcomes():
    result = _make_result(
        [
            _dynamic_finding("bypassed", "IOS-DYN-001"),
            _dynamic_finding("resistant", "IOS-DYN-002"),
            _dynamic_finding("unavailable", "IOS-DYN-003"),
        ]
    )
    d = result.to_dict()
    assert d["summary"]["dynamic"]["total"] == 3
    assert d["summary"]["dynamic"]["bypassed"] == 1
    assert d["summary"]["dynamic"]["resistant"] == 1
    assert d["summary"]["static"]["total"] == 0


def test_summary_backward_compatible_keys():
    """Existing summary keys must remain present and correct."""
    result = _make_result(
        [
            Finding("A", "t", Severity.HIGH, "d"),
            Finding("B", "t", Severity.MEDIUM, "d"),
            _dynamic_finding("bypassed"),
        ]
    )
    s = result.to_dict()["summary"]
    assert s["high"] == 2  # 1 static + 1 dynamic bypassed (HIGH)
    assert s["medium"] == 1
    assert s["low"] == 0
    assert s["total"] == 3
    assert "suppressed" in s


# ── pt_deny_attach: lldb parsing ──────────────────────────────────────────────


def test_pt_deny_attach_resistant_on_timeout():
    from shingan.core.dynamic.checks.pt_deny_attach import _attempt_lldb_attach
    import subprocess

    with patch("subprocess.run") as mock_run:
        mock_run.side_effect = subprocess.TimeoutExpired(cmd=["lldb"], timeout=15)
        result = _attempt_lldb_attach(pid=12345, timeout=15)

    assert result["outcome"] == "resistant"
    assert "timed out" in result["detail"]


def test_pt_deny_attach_unavailable_when_lldb_missing():
    from shingan.core.dynamic.checks.pt_deny_attach import _attempt_lldb_attach

    with patch("subprocess.run", side_effect=FileNotFoundError):
        result = _attempt_lldb_attach(pid=12345)

    assert result["outcome"] == "unavailable"
    assert "lldb" in result["detail"]


def test_pt_deny_attach_bypassed_on_successful_attach():
    from shingan.core.dynamic.checks.pt_deny_attach import _attempt_lldb_attach

    mock_result = MagicMock()
    mock_result.stdout = "process attach stopped\nthread list ..."
    mock_result.stderr = ""
    mock_result.returncode = 0

    with patch("subprocess.run", return_value=mock_result):
        result = _attempt_lldb_attach(pid=12345)

    assert result["outcome"] == "bypassed"


def test_pt_deny_attach_resistant_on_permission_denied():
    from shingan.core.dynamic.checks.pt_deny_attach import _attempt_lldb_attach

    mock_result = MagicMock()
    mock_result.stdout = ""
    mock_result.stderr = "error: attach failed — ptrace: Operation not permitted"
    mock_result.returncode = 1

    with patch("subprocess.run", return_value=mock_result):
        result = _attempt_lldb_attach(pid=12345)

    assert result["outcome"] == "resistant"


# ── device listing: xcrun fallback ────────────────────────────────────────────


def test_list_simulators_returns_empty_on_xcrun_failure():
    from shingan.core.dynamic.device import _list_simulators_via_xcrun

    with patch("subprocess.run", side_effect=FileNotFoundError):
        result = _list_simulators_via_xcrun()

    assert result == []


def test_list_simulators_parses_booted_only():
    from shingan.core.dynamic.device import _list_simulators_via_xcrun
    import json

    fake_output = json.dumps(
        {
            "devices": {
                "com.apple.CoreSimulator.SimRuntime.iOS-17-4": [
                    {"udid": "ABC-123", "name": "iPhone 15", "state": "Booted"},
                    {"udid": "DEF-456", "name": "iPhone 14", "state": "Shutdown"},
                ]
            }
        }
    )

    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = fake_output

    with patch("subprocess.run", return_value=mock_result):
        devices = _list_simulators_via_xcrun()

    assert len(devices) == 1
    assert devices[0].udid == "ABC-123"
    assert devices[0].kind == "simulator"
    assert devices[0].os_version == "iOS 17.4"


# ── device listing: adb emulator ─────────────────────────────────────────────


def test_list_emulators_via_adb_parses_emulator():
    from shingan.core.dynamic.device import _list_emulators_via_adb

    adb_output = (
        "List of devices attached\n"
        "emulator-5554          device product:sdk_gphone_x86_64 model:sdk_gphone_x86_64 device:emu64xa\n"
        "192.168.1.10:5555      device product:taimen model:Pixel_2 device:taimen\n"
    )
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = adb_output

    with patch("subprocess.run") as mock_run:
        mock_run.side_effect = [
            mock_proc,  # adb devices -l
            MagicMock(stdout="10"),  # getprop emulator-5554
            MagicMock(stdout="14"),  # getprop 192.168.1.10:5555
        ]
        devices = _list_emulators_via_adb()

    assert len(devices) == 2
    emu = next(d for d in devices if d.udid == "emulator-5554")
    assert emu.kind == "emulator"
    assert emu.os_version == "Android 10"

    real = next(d for d in devices if d.udid == "192.168.1.10:5555")
    assert real.kind == "usb"


def test_list_emulators_returns_empty_on_adb_failure():
    from shingan.core.dynamic.device import _list_emulators_via_adb

    with patch("subprocess.run", side_effect=FileNotFoundError):
        result = _list_emulators_via_adb()

    assert result == []


def test_list_emulators_skips_offline():
    from shingan.core.dynamic.device import _list_emulators_via_adb

    adb_output = "List of devices attached\nemulator-5554          offline\n"
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = adb_output

    with patch("subprocess.run", return_value=mock_proc):
        devices = _list_emulators_via_adb()

    assert devices == []
