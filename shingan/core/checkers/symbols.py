"""IOS-SYM-001: Debug symbols / Objective-C metadata exposure.

Checks whether the main binary retains debug symbols, ObjC class/method names,
or Swift mangled symbols that assist reverse engineering.
"""

from __future__ import annotations

import lief
from pathlib import Path

from shingan.core.models import Finding, Severity


def check(binary_path: Path) -> list[Finding]:
    findings: list[Finding] = []

    binary = lief.parse(str(binary_path))
    if binary is None:
        return findings

    # --- 1. Debug symbols (STABS / DWARF) ---
    debug_syms: list[str] = []
    for sym in binary.symbols:
        # STABS debug symbols start with N_SO, N_FUN, etc. (type >= 0x20 odd)
        if hasattr(sym, "type") and sym.type != lief.MachO.Symbol.TYPE.UNDEFINED:
            name = sym.name
            if name.startswith("_") or name.startswith("$"):
                debug_syms.append(name)

    # Narrower signal: look for typical debug-only symbols
    suspicious = [
        s
        for s in debug_syms
        if any(
            marker in s for marker in ["__debug", "_DWARF", "llvm_dbg", "__sanitizer"]
        )
    ]
    if suspicious:
        findings.append(
            Finding(
                rule_id="IOS-SYM-001a",
                title="Debug symbols present in binary",
                severity=Severity.MEDIUM,
                description=(
                    "The binary contains debug or sanitizer symbols. These help attackers "
                    "understand internal structure and reconstruct function names."
                ),
                evidence="\n".join(suspicious[:20]),
                recommendation=(
                    "Build with DEBUG_INFORMATION_FORMAT=dwarf-with-dsym and strip the binary. "
                    "Use STRIP_INSTALLED_PRODUCT=YES in release builds."
                ),
            )
        )

    # --- 2. Objective-C class/method metadata ---
    objc_classes: list[str] = []
    try:
        for cls in binary.objc_classes:
            objc_classes.append(cls.name)
    except Exception:
        pass

    if objc_classes:
        sample = objc_classes[:30]
        findings.append(
            Finding(
                rule_id="IOS-SYM-001b",
                title="Objective-C class metadata exposed",
                severity=Severity.MEDIUM,
                description=(
                    f"{len(objc_classes)} Objective-C class(es) are readable in the binary. "
                    "Class and method names expose application structure to attackers."
                ),
                evidence="\n".join(sample)
                + (
                    f"\n… and {len(objc_classes) - 30} more"
                    if len(objc_classes) > 30
                    else ""
                ),
                recommendation=(
                    "Consider using a Swift-based implementation where possible, or apply "
                    "an obfuscation tool (e.g. iXGuard, Guardsquare) to rename symbols in release builds."
                ),
                extra={"total_classes": len(objc_classes)},
            )
        )

    # --- 3. Swift symbols (demanglable = readable names) ---
    swift_syms = [
        sym.name
        for sym in binary.symbols
        if sym.name.startswith("$s") or sym.name.startswith("_$s")
    ]
    if swift_syms:
        sample = swift_syms[:20]
        findings.append(
            Finding(
                rule_id="IOS-SYM-001c",
                title="Swift mangled symbols present (demanglable)",
                severity=Severity.LOW,
                description=(
                    f"{len(swift_syms)} Swift symbol(s) found. While mangled, they can be "
                    "demangled with `swift-demangle` to reveal class/function names."
                ),
                evidence="\n".join(sample[:10]),
                recommendation=(
                    "Strip Swift symbols in release builds using STRIP_SWIFT_SYMBOLS=YES. "
                    "Apply obfuscation for high-security apps."
                ),
                extra={"total_swift_syms": len(swift_syms)},
            )
        )

    return findings
