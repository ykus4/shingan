"""Device / simulator enumeration for dynamic analysis."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass

from shingan.core.shell import run_command

logger = logging.getLogger(__name__)

#: Timeout for quick device-enumeration commands (seconds).
_ENUMERATION_TIMEOUT = 10

#: Timeout for a single `adb shell getprop` call (seconds).
_GETPROP_TIMEOUT = 5


@dataclass
class DeviceInfo:
    udid: str
    name: str
    kind: str  # "usb" | "simulator" | "emulator" | "remote"
    os_version: str


def list_devices() -> list[DeviceInfo]:
    """Return all reachable devices, simulators, and Android emulators.

    Tries frida first for USB/remote devices, then xcrun for iOS simulators,
    then adb for Android emulators.
    Never raises — returns empty list on total failure.
    """
    devices: list[DeviceInfo] = []
    devices += _list_via_frida()
    existing_udids = {d.udid for d in devices}
    for sim in _list_simulators_via_xcrun():
        if sim.udid not in existing_udids:
            devices.append(sim)
            existing_udids.add(sim.udid)
    for emu in _list_emulators_via_adb():
        if emu.udid not in existing_udids:
            devices.append(emu)
            existing_udids.add(emu.udid)
    return devices


def _list_via_frida() -> list[DeviceInfo]:
    try:
        import frida

        result = []
        for dev in frida.enumerate_devices():
            if dev.type not in ("usb", "remote"):
                continue
            os_ver = "unknown"
            try:
                params = dev.query_system_parameters()
                os_ver = params.get("os", {}).get("version", "unknown")
            except Exception as exc:
                logger.debug("Could not query OS version for %s: %s", dev.id, exc)
            result.append(
                DeviceInfo(udid=dev.id, name=dev.name, kind=dev.type, os_version=os_ver)
            )
        return result
    except ImportError:
        return []
    except Exception as exc:
        logger.debug("frida enumerate_devices failed: %s", exc)
        return []


def _list_emulators_via_adb() -> list[DeviceInfo]:
    """Parse `adb devices -l` for connected Android devices and emulators."""
    result_cmd = run_command(["adb", "devices", "-l"], timeout=_ENUMERATION_TIMEOUT)
    if not result_cmd.ok:
        return []
    try:
        result = []
        for raw_line in result_cmd.lines()[1:]:  # skip "List of devices attached"
            line = raw_line.strip()
            if not line or "offline" in line:
                continue
            parts = line.split()
            if len(parts) < 2 or parts[1] != "device":
                continue
            serial = parts[0]  # e.g. "emulator-5554" or "192.168.1.10:5555"
            # Parse model / product from remaining tokens (key:value pairs)
            props = dict(p.split(":", 1) for p in parts[2:] if ":" in p)
            model = props.get("model", props.get("product", serial))
            kind = "emulator" if serial.startswith("emulator-") else "usb"
            # Fetch Android version via adb shell
            os_ver = _adb_get_prop(serial, "ro.build.version.release")
            result.append(
                DeviceInfo(
                    udid=serial,
                    name=model.replace("_", " "),
                    kind=kind,
                    os_version=f"Android {os_ver}" if os_ver else "Android",
                )
            )
        return result
    except Exception as exc:
        logger.debug("adb devices failed: %s", exc)
        return []


def _adb_get_prop(serial: str, prop: str) -> str:
    """Return an Android system property via adb shell getprop."""
    result = run_command(
        ["adb", "-s", serial, "shell", "getprop", prop], timeout=_GETPROP_TIMEOUT
    )
    return result.stdout.strip() if result.ok else ""


def _list_simulators_via_xcrun() -> list[DeviceInfo]:
    """Parse `xcrun simctl list devices --json` for booted simulators."""
    proc = run_command(
        ["xcrun", "simctl", "list", "devices", "--json"], timeout=_ENUMERATION_TIMEOUT
    )
    if not proc.ok:
        return []
    try:
        data = json.loads(proc.stdout)
        result = []
        for runtime_key, sims in data.get("devices", {}).items():
            # e.g. "com.apple.CoreSimulator.SimRuntime.iOS-17-4" → "iOS 17.4"
            suffix = runtime_key.split(".")[-1]  # "iOS-17-4"
            parts = suffix.split("-")
            os_ver = f"{parts[0]} {'.'.join(parts[1:])}" if len(parts) >= 3 else suffix
            for sim in sims:
                if sim.get("state") != "Booted":
                    continue
                result.append(
                    DeviceInfo(
                        udid=sim["udid"],
                        name=sim["name"],
                        kind="simulator",
                        os_version=os_ver,
                    )
                )
        return result
    except Exception as exc:
        logger.debug("xcrun simctl list failed: %s", exc)
        return []
