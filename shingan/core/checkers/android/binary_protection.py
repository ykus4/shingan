"""AND-RASP-006/007: Binary protection checks on bundled .so ELF libraries.

Uses LIEF (already a dependency) to inspect ELF security mitigations:
  - AND-RASP-006: PIE (Position Independent Executable)
  - AND-RASP-007a: NX bit (non-executable stack/heap)
  - AND-RASP-007b: Stack canary (stack smashing protection)
  - AND-RASP-007c: RELRO (read-only relocations)
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from shingan.core.context import AndroidCheckContext
from shingan.core.models import Finding, Severity

logger = logging.getLogger(__name__)


def check(ctx: AndroidCheckContext) -> list[Finding]:
    findings: list[Finding] = []
    native_libs = ctx.native_binaries

    if not native_libs:
        return findings

    no_pie: list[str] = []
    no_nx: list[str] = []
    no_canary: list[str] = []
    no_relro: list[str] = []

    for so_path in native_libs:
        binary = _parse_elf(so_path)
        if binary is None:
            continue
        name = so_path.name
        try:
            if not _has_pie(binary):
                no_pie.append(name)
            if not _has_nx(binary):
                no_nx.append(name)
            if not _has_stack_canary(binary):
                no_canary.append(name)
            if not _has_relro(binary):
                no_relro.append(name)
        except Exception as exc:
            logger.debug("Binary protection check failed for %s: %s", name, exc)

    if no_pie:
        findings.append(
            Finding(
                rule_id="AND-RASP-006",
                title=f"{len(no_pie)} native library/libraries compiled without PIE",
                severity=Severity.MEDIUM,
                description=(
                    "Position Independent Executables (PIE) are required for ASLR to be effective. "
                    "Non-PIE libraries are loaded at predictable addresses, making exploitation easier."
                ),
                evidence="\n".join(no_pie[:10]),
                recommendation="Compile all native libraries with `-fPIC` and link with `-pie`.",
                masvs="MASVS-RESILIENCE-3",
            )
        )

    if no_nx:
        findings.append(
            Finding(
                rule_id="AND-RASP-007a",
                title=f"{len(no_nx)} native library/libraries missing NX bit",
                severity=Severity.HIGH,
                description=(
                    "The NX (No-eXecute) bit prevents shellcode from running in data segments. "
                    "Libraries without NX enabled are vulnerable to classic stack/heap exploitation."
                ),
                evidence="\n".join(no_nx[:10]),
                recommendation=(
                    "Ensure libraries are compiled without `-z execstack`. "
                    "Modern NDK builds enable NX by default."
                ),
                masvs="MASVS-RESILIENCE-3",
            )
        )

    if no_canary:
        findings.append(
            Finding(
                rule_id="AND-RASP-007b",
                title=f"{len(no_canary)} native library/libraries missing stack canary",
                severity=Severity.MEDIUM,
                description=(
                    "Stack canaries detect stack buffer overflows before a return address is "
                    "overwritten. Libraries without canaries are more vulnerable to stack-based attacks."
                ),
                evidence="\n".join(no_canary[:10]),
                recommendation="Compile native libraries with `-fstack-protector-strong`.",
                masvs="MASVS-RESILIENCE-3",
            )
        )

    if no_relro:
        findings.append(
            Finding(
                rule_id="AND-RASP-007c",
                title=f"{len(no_relro)} native library/libraries missing RELRO",
                severity=Severity.LOW,
                description=(
                    "RELRO (RELocation Read-Only) marks the GOT/PLT as read-only after dynamic "
                    "linking, preventing GOT overwrite attacks. Libraries without RELRO are more "
                    "vulnerable to memory-corruption-based code reuse attacks."
                ),
                evidence="\n".join(no_relro[:10]),
                recommendation="Link native libraries with `-Wl,-z,relro,-z,now`.",
                masvs="MASVS-RESILIENCE-3",
            )
        )

    return findings


def _parse_elf(path: Path) -> Any | None:
    try:
        import lief  # type: ignore[import]

        binary = lief.parse(str(path))
        if binary is None or not isinstance(binary, lief.ELF.Binary):
            return None
        return binary
    except Exception as exc:
        logger.debug("lief.parse failed for %s: %s", path, exc)
        return None


def _has_pie(binary: Any) -> bool:
    try:
        return binary.is_pie
    except Exception:
        return True  # assume safe if check fails


def _has_nx(binary: Any) -> bool:
    try:
        return binary.has_nx
    except Exception:
        return True


def _has_stack_canary(binary: Any) -> bool:
    try:
        symbol_names = {sym.name for sym in binary.symbols}
        return "__stack_chk_fail" in symbol_names or "__stack_chk_guard" in symbol_names
    except Exception:
        return True


def _has_relro(binary: Any) -> bool:
    try:
        import lief  # type: ignore[import]

        for seg in binary.segments:
            if seg.type in (
                lief.ELF.Segment.TYPE.GNU_RELRO,
                lief.ELF.Segment.TYPE.GNU_RELRO,
            ):
                return True
        # Also check dynamic entries for BIND_NOW (full RELRO)
        for entry in binary.dynamic_entries:
            if entry.tag == lief.ELF.DynamicEntry.TAG.FLAGS:
                return bool(entry.value & 0x8)  # DF_BIND_NOW
        return False
    except Exception:
        return True
