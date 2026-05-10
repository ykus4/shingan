"""IOS-RASP-006/007/008: Binary hardening flags.

Checks for PIE, stack canary, and ARC via Mach-O load commands and symbol table.
"""

from __future__ import annotations

from shingan.core.binary import CheckContext
from shingan.core.models import Finding, Severity


def check(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    binary = ctx.lief_binary
    if binary is None:
        return findings

    # --- 1. PIE (Position Independent Executable) ---
    if not binary.is_pie:
        findings.append(
            Finding(
                rule_id="IOS-RASP-006-missing",
                title="PIE (Position Independent Executable) is not enabled",
                severity=Severity.HIGH,
                description=(
                    "The binary is not compiled as a PIE. Without PIE, the executable "
                    "is loaded at a fixed address, making ROP/JOP attacks significantly easier."
                ),
                evidence="MH_PIE flag not set in Mach-O header",
                recommendation=(
                    "Enable PIE by setting ENABLE_PIE=YES in your Xcode build settings. "
                    "This is required for all iOS apps submitted to the App Store since iOS 4.3."
                ),
                masvs="MASVS-RESILIENCE-3",
            )
        )
    else:
        findings.append(
            Finding(
                rule_id="IOS-RASP-006-found",
                title="PIE is enabled",
                severity=Severity.INFO,
                description="The binary is compiled as a Position Independent Executable.",
                evidence="MH_PIE flag set",
                recommendation="No action required.",
                masvs="MASVS-RESILIENCE-3",
            )
        )

    # --- 2. Stack canary ---
    has_canary = any(
        s in ctx.symbol_names
        for s in ("___stack_chk_fail", "___stack_chk_guard", "__stack_chk_fail")
    )
    if not has_canary:
        findings.append(
            Finding(
                rule_id="IOS-RASP-007-missing",
                title="Stack canary not detected",
                severity=Severity.MEDIUM,
                description=(
                    "No stack canary symbols found. Stack canaries help detect stack buffer "
                    "overflows before a return address is overwritten."
                ),
                evidence="___stack_chk_fail / ___stack_chk_guard not found in symbol table",
                recommendation=(
                    "Enable stack protection with -fstack-protector-all in compiler flags. "
                    "In Xcode, set OTHER_CFLAGS = -fstack-protector-all."
                ),
                masvs="MASVS-RESILIENCE-3",
            )
        )
    else:
        findings.append(
            Finding(
                rule_id="IOS-RASP-007-found",
                title="Stack canary is present",
                severity=Severity.INFO,
                description="Stack canary symbols detected in the binary.",
                evidence="___stack_chk_fail found in symbol table",
                recommendation="No action required.",
                masvs="MASVS-RESILIENCE-3",
            )
        )

    # --- 3. ARC (Automatic Reference Counting) ---
    has_arc = any(
        s in ctx.symbol_names
        for s in ("_objc_retain", "_objc_release", "_objc_autorelease")
    )
    has_objc = bool(ctx.objc_classes)
    if has_objc and not has_arc:
        findings.append(
            Finding(
                rule_id="IOS-RASP-008-missing",
                title="ARC (Automatic Reference Counting) not detected in ObjC binary",
                severity=Severity.MEDIUM,
                description=(
                    "The binary contains Objective-C classes but ARC runtime symbols are absent. "
                    "Manual memory management increases the risk of use-after-free vulnerabilities."
                ),
                evidence="_objc_retain / _objc_release not found",
                recommendation=(
                    "Enable ARC by setting CLANG_ENABLE_OBJC_ARC=YES in build settings."
                ),
                masvs="MASVS-RESILIENCE-3",
            )
        )
    elif has_arc:
        findings.append(
            Finding(
                rule_id="IOS-RASP-008-found",
                title="ARC is enabled",
                severity=Severity.INFO,
                description="ARC runtime symbols detected.",
                evidence="_objc_retain found in symbol table",
                recommendation="No action required.",
                masvs="MASVS-RESILIENCE-3",
            )
        )

    return findings
