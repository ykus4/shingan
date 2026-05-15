"""DynamicContext — live device session for dynamic checks."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class DynamicContext:
    """Wraps a Frida device + session for a running app process.

    Usage::

        with DynamicContext(bundle_id="com.example.app") as ctx:
            session = ctx.attach()
            ...
    """

    bundle_id: str
    device_udid: str | None = None
    timeout: int = 30

    _device: Any = field(default=None, init=False, repr=False)
    _session: Any = field(default=None, init=False, repr=False)

    def get_device(self) -> Any:
        """Return frida.Device (lazy). Raises ImportError if frida is absent."""
        if self._device is not None:
            return self._device
        import frida  # optional — ImportError propagates to caller

        if self.device_udid:
            self._device = frida.get_device(self.device_udid, timeout=self.timeout)
        else:
            self._device = frida.get_usb_device(timeout=self.timeout)
        return self._device

    def attach(self) -> Any:
        """Attach to the running app process and return frida.Session."""
        if self._session is not None:
            return self._session
        device = self.get_device()
        self._session = device.attach(self.bundle_id)
        return self._session

    def detach(self) -> None:
        if self._session:
            try:
                self._session.detach()
            except Exception:
                pass
            self._session = None

    def __enter__(self) -> DynamicContext:
        return self

    def __exit__(self, *_: object) -> None:
        self.detach()
