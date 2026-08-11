"""IOS-SYM-001: Debug symbols / Objective-C metadata exposure.

Checks whether the main binary retains debug symbols, ObjC class/method names,
or Swift mangled symbols that assist reverse engineering.
"""

from __future__ import annotations

from shingan.core.constants import EVIDENCE_OBJC_SAMPLE, EVIDENCE_SWIFT_SAMPLE
from shingan.core.context import CheckContext
from shingan.core.models import Finding, Severity


def check(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    binary = ctx.lief_binary
    if binary is None:
        return findings

    # --- 1. Debug symbols (STABS / DWARF) ---
    try:
        import lief

        suspicious = [
            sym.name
            for sym in binary.symbols
            if (
                hasattr(sym, "type")
                and sym.type != lief.MachO.Symbol.TYPE.UNDEFINED
                and any(
                    marker in sym.name
                    for marker in ["__debug", "_DWARF", "llvm_dbg", "__sanitizer"]
                )
            )
        ]
    except Exception:
        suspicious = []

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
                masvs="MASVS-RESILIENCE-3",
            )
        )

    # --- 2. Objective-C class/method metadata ---
    objc_classes = ctx.objc_classes
    if objc_classes:
        sample = objc_classes[:EVIDENCE_OBJC_SAMPLE]
        overflow = len(objc_classes) - EVIDENCE_OBJC_SAMPLE
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
                + (f"\n… and {overflow} more" if overflow > 0 else ""),
                recommendation=(
                    "Consider using a Swift-based implementation where possible, or apply "
                    "an obfuscation tool (e.g. iXGuard, Guardsquare) to rename symbols in release builds."
                ),
                extra={"total_classes": len(objc_classes)},
                masvs="MASVS-RESILIENCE-3",
            )
        )

    # --- 3. Swift symbols (demanglable = readable names) ---
    swift_syms = [name for name in ctx.symbol_names if name.startswith(("$s", "_$s"))]
    if swift_syms:
        sample = swift_syms[:EVIDENCE_SWIFT_SAMPLE]
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
                masvs="MASVS-RESILIENCE-3",
            )
        )

    return findings
