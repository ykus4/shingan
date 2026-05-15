"""Device / simulator enumeration for dynamic analysis."""

from __future__ import annotations

import json
import logging
import subprocess
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class DeviceInfo:
    udid: str
    name: str
    kind: str  # "usb" | "simulator" | "remote"
    os_version: str


def list_devices() -> list[DeviceInfo]:
    """Return all reachable devices and booted simulators.

    Tries frida first for USB/remote devices, then xcrun for simulators.
    Never raises — returns empty list on total failure.
    """
    devices: list[DeviceInfo] = []
    devices += _list_via_frida()
    existing_udids = {d.udid for d in devices}
    for sim in _list_simulators_via_xcrun():
        if sim.udid not in existing_udids:
            devices.append(sim)
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
            except Exception:
                pass
            result.append(
                DeviceInfo(udid=dev.id, name=dev.name, kind=dev.type, os_version=os_ver)
            )
        return result
    except ImportError:
        return []
    except Exception as exc:
        logger.debug("frida enumerate_devices failed: %s", exc)
        return []


def _list_simulators_via_xcrun() -> list[DeviceInfo]:
    """Parse `xcrun simctl list devices --json` for booted simulators."""
    try:
        proc = subprocess.run(
            ["xcrun", "simctl", "list", "devices", "--json"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if proc.returncode != 0:
            return []
        data = json.loads(proc.stdout)
        result = []
        for runtime_key, sims in data.get("devices", {}).items():
            # e.g. "com.apple.CoreSimulator.SimRuntime.iOS-17-4" → "iOS 17.4"
            suffix = runtime_key.split(".")[-1]  # "iOS-17-4"
            parts = suffix.split("-")
            if len(parts) >= 3:
                os_ver = f"{parts[0]} {'.'.join(parts[1:])}"
            else:
                os_ver = suffix
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
