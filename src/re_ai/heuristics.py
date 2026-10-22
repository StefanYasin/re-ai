"""Packer and hardening heuristics.

Everything here is a rule with a stated reason. None of it is a verdict: a
single finding is a hint, several together are worth following up.
"""

from __future__ import annotations

from dataclasses import dataclass

from .pe import DIR_TLS, PEInfo, Section

HIGH = "high"
MEDIUM = "medium"
LOW = "low"
INFO = "info"

SEVERITY_WEIGHTS = {HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0}

PACKER_SECTION_NAMES = {
    "upx0",
    "upx1",
    "upx2",
    ".upx",
    ".aspack",
    ".adata",
    ".themida",
    ".vmp0",
    ".vmp1",
    ".vmp2",
    ".mpress1",
    ".mpress2",
    ".petite",
    ".nsp0",
    ".nsp1",
    ".packed",
    ".pack",
    ".boom",
    ".ccg",
    ".enigma1",
    ".enigma2",
    ".pec1",
    ".pec2",
    ".mew",
    ".svkp",
    ".taz",
    ".y0da",
    ".rmnet",
    ".perplex",
    ".shrink1",
    ".shrink2",
}

COMMON_SECTION_NAMES = {
    ".text",
    ".data",
    ".rdata",
    ".rsrc",
    ".reloc",
    ".bss",
    ".idata",
    ".edata",
    ".tls",
    ".debug",
    ".pdata",
    ".xdata",
    ".crt",
    ".didat",
    ".gfids",
    ".00cfg",
    ".voltbl",
}

SUSPICIOUS_APIS = {
    "VirtualAlloc",
    "VirtualAllocEx",
    "VirtualProtect",
    "WriteProcessMemory",
    "ReadProcessMemory",
    "CreateRemoteThread",
    "CreateRemoteThreadEx",
    "NtUnmapViewOfSection",
    "SetThreadContext",
    "QueueUserAPC",
    "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent",
    "OutputDebugStringA",
    "LoadLibraryA",
    "LoadLibraryW",
    "GetProcAddress",
    "WinExec",
    "ShellExecuteA",
    "ShellExecuteW",
    "URLDownloadToFileA",
    "URLDownloadToFileW",
    "InternetOpenA",
    "InternetOpenW",
    "HttpSendRequestA",
    "CreateServiceA",
    "CreateServiceW",
    "AdjustTokenPrivileges",
    "OpenProcessToken",
    "CryptDecrypt",
    "CryptEncrypt",
}


@dataclass(frozen=True)
class Finding:
    severity: str
    title: str
    detail: str


def score(findings: list[Finding]) -> int:
    return sum(SEVERITY_WEIGHTS.get(finding.severity, 0) for finding in findings)


def verdict(findings: list[Finding]) -> str:
    """One line assessment derived from the findings."""
    total = score(findings)
    highs = sum(1 for finding in findings if finding.severity == HIGH)
    if highs >= 2 or total >= 7:
        return "strong indicators of packing, encryption, or deliberate obfuscation"
    if highs == 1 or total >= 4:
        return "several indicators worth a closer look"
    if total >= 1:
        return "a few weak indicators, nothing conclusive"
    return "no notable packer or obfuscation indicators"


def _section_entropy_findings(sections: list[Section]) -> list[Finding]:
    findings: list[Finding] = []
    for section in sections:
        if section.raw_size < 1024:
            continue
        if section.entropy >= 7.4:
            findings.append(
                Finding(
                    HIGH,
                    f"Section {section.name} is close to random data",
                    f"Entropy {section.entropy:.3f} bits per byte over "
                    f"{section.raw_size} bytes. Compressed or encrypted payloads "
                    "look like this.",
                )
            )
        elif section.entropy >= 7.0:
            findings.append(
                Finding(
                    MEDIUM,
                    f"Section {section.name} has high entropy",
                    f"Entropy {section.entropy:.3f} bits per byte over "
                    f"{section.raw_size} bytes, which is above what compiled code "
                    "normally produces.",
                )
            )
    return findings


def _packer_name_findings(sections: list[Section]) -> list[Finding]:
    hits = [
        section.name
        for section in sections
        if section.name.strip().lower() in PACKER_SECTION_NAMES
    ]
    if not hits:
        return []
    return [
        Finding(
            HIGH,
            "Section names match known packers",
            "Sections named "
            + ", ".join(hits)
            + " are used by UPX, ASProtect, Themida, VMProtect and friends.",
        )
    ]


def _memory_permission_findings(sections: list[Section]) -> list[Finding]:
    findings: list[Finding] = []
    wx = [section for section in sections if section.writable and section.executable]
    for section in wx:
        findings.append(
            Finding(
                MEDIUM,
                f"Section {section.name} is writable and executable",
                "W + X sections are uncommon in normal builds and are typical of "
                "unpacking stubs and injected code.",
            )
        )
    return findings


def _import_findings(pe: PEInfo) -> list[Finding]:
    findings: list[Finding] = []
    total = len(pe.imports)
    has_import_dir = bool(pe.directory(1)[0])
    if total == 0:
        if has_import_dir:
            findings.append(
                Finding(
                    HIGH,
                    "Import directory is present but empty",
                    "The import directory exists yet no thunks resolved, which is "
                    "what a binary that resolves its API at runtime looks like.",
                )
            )
        else:
            findings.append(
                Finding(
                    MEDIUM,
                    "No import table",
                    "No import directory at all. Statically linked or packed "
                    "binaries often look like this.",
                )
            )
    elif total <= 5:
        noun = "function" if total == 1 else "functions"
        findings.append(
            Finding(
                MEDIUM,
                f"Only {total} imported {noun}",
                "Small import tables are common in loaders that resolve the rest "
                "of their API dynamically.",
            )
        )

    suspicious = sorted(
        {
            ref.name
            for ref in pe.imports
            if ref.name and ref.name in SUSPICIOUS_APIS
        }
    )
    if suspicious:
        findings.append(
            Finding(
                INFO,
                f"{len(suspicious)} behaviourally interesting imports",
                ", ".join(suspicious[:12]) + (" ..." if len(suspicious) > 12 else ""),
            )
        )
    return findings


def _layout_findings(
    pe: PEInfo,
    overlay_size: int,
    overlay_entropy: float,
    overlay_start: int = 0,
    file_size: int = 0,
) -> list[Finding]:
    findings: list[Finding] = []

    for section in pe.sections:
        if section.raw_size == 0 and section.virtual_size > 0:
            findings.append(
                Finding(
                    INFO,
                    f"Section {section.name} exists only in memory",
                    f"Virtual size 0x{section.virtual_size:x} with no file data.",
                )
            )
            continue
        if section.raw_size and section.virtual_size > section.raw_size * 5 and section.virtual_size > 0x2000:
            findings.append(
                Finding(
                    MEDIUM,
                    f"Section {section.name} expands heavily in memory",
                    f"Virtual size 0x{section.virtual_size:x} against "
                    f"0x{section.raw_size:x} on disk. Unpacking stubs usually "
                    "claim a large buffer before writing the real image into it.",
                )
            )

    entry_section = pe.section_for_rva(pe.entry_point)
    if entry_section is None:
        findings.append(
            Finding(
                HIGH,
                "Entry point is outside every section",
                f"AddressOfEntryPoint 0x{pe.entry_point:x} does not fall inside any "
                "section, which a normal linker output never does.",
            )
        )
    elif entry_section is pe.sections[-1] and entry_section.entropy >= 7.0:
        findings.append(
            Finding(
                MEDIUM,
                "Entry point sits in the last, high entropy section",
                f"Entry point 0x{pe.entry_point:x} is in {entry_section.name}, which "
                "has entropy "
                f"{entry_section.entropy:.3f}. Packers often put a small stub at the "
                "end of the section list and jump into the unpacked image from there.",
            )
        )

    if overlay_size > 0:
        symbols_in_overlay = (
            bool(pe.pointer_to_symbol_table and pe.number_of_symbols)
            and overlay_start > 0
            and pe.pointer_to_symbol_table >= overlay_start
            and (not file_size or pe.pointer_to_symbol_table < file_size)
        )
        if symbols_in_overlay:
            findings.append(
                Finding(
                    INFO,
                    f"Overlay data after the last section ({overlay_size} bytes)",
                    f"Entropy {overlay_entropy:.3f} bits per byte. The COFF symbol "
                    f"table starts at 0x{pe.pointer_to_symbol_table:x} inside this "
                    "region, so most of it is probably unstripped debug information "
                    "rather than an appended payload.",
                )
            )
        else:
            severity = MEDIUM if overlay_entropy >= 7.2 else LOW
            findings.append(
                Finding(
                    severity,
                    f"Overlay data after the last section ({overlay_size} bytes)",
                    f"Entropy {overlay_entropy:.3f} bits per byte. Installers append "
                    "payloads this way, and so do droppers.",
                )
            )

    if pe.directory(DIR_TLS)[0]:
        findings.append(
            Finding(
                INFO,
                "TLS directory present",
                "TLS callbacks run before the entry point, which is a known anti "
                "debugging and early execution trick.",
            )
        )

    if pe.has_signature:
        findings.append(
            Finding(INFO, "Authenticode certificate table present", "The file carries a signature blob. Verify it before trusting it.")
        )
    else:
        findings.append(Finding(INFO, "No Authenticode signature", "The certificate table is empty."))
    return findings


def _string_findings(strings: list) -> list[Finding]:
    findings: list[Finding] = []
    hits = [item for item in strings if item.is_interesting]
    if hits:
        distinct: list[str] = []
        for item in hits:
            if item.value not in distinct:
                distinct.append(item.value)
        sample = ", ".join(value[:60] for value in distinct[:5])
        findings.append(
            Finding(
                INFO,
                f"{len(hits)} strings match behaviour keywords",
                sample,
            )
        )
    pdbs = [item.value for item in strings if item.value.lower().endswith(".pdb")]
    if pdbs:
        findings.append(
            Finding(
                INFO,
                "Debug path left in the binary",
                pdbs[0][:120],
            )
        )
    return findings


def check_all(
    pe: PEInfo,
    strings: list,
    overall_entropy: float,
    overlay_size: int = 0,
    overlay_entropy: float = 0.0,
    overlay_start: int = 0,
    file_size: int = 0,
) -> list[Finding]:
    """Run every check and return findings ordered by severity."""
    findings: list[Finding] = []

    if overall_entropy >= 7.2:
        findings.append(
            Finding(
                HIGH,
                "File entropy is near random",
                f"{overall_entropy:.3f} bits per byte across the whole file. Files "
                "this dense are almost always compressed or encrypted.",
            )
        )
    elif overall_entropy >= 6.9:
        findings.append(
            Finding(
                MEDIUM,
                "File entropy is high",
                f"{overall_entropy:.3f} bits per byte across the whole file.",
            )
        )

    findings.extend(_section_entropy_findings(pe.sections))
    findings.extend(_packer_name_findings(pe.sections))
    findings.extend(_memory_permission_findings(pe.sections))
    findings.extend(_import_findings(pe))

    # Dot names are conventional. Unresolved /NNN names are a COFF formatting
    # artifact, not a signal, so both are left alone here.
    unusual = [
        section.name
        for section in pe.sections
        if section.name
        and not section.name.startswith((".", "/"))
        and section.name.strip().lower() not in COMMON_SECTION_NAMES
    ]
    if unusual:
        findings.append(
            Finding(
                LOW,
                "Non standard section names",
                ", ".join(unusual) + " do not match the names a stock linker emits.",
            )
        )

    findings.extend(
        _layout_findings(pe, overlay_size, overlay_entropy, overlay_start, file_size)
    )
    findings.extend(_string_findings(strings))

    order = {HIGH: 0, MEDIUM: 1, LOW: 2, INFO: 3}
    findings.sort(key=lambda finding: order.get(finding.severity, 4))
    return findings
