"""Heuristic rules are pure functions of a PEInfo and some numbers."""

from __future__ import annotations

import pytest

from re_ai.heuristics import (
    HIGH,
    INFO,
    LOW,
    MEDIUM,
    Finding,
    check_all,
    score,
    verdict,
)
from re_ai.pe import ImportRef, PEInfo, Section
from re_ai.strings import ExtractedString

CODE = 0x60000020
CODE_WRITE = 0xE0000020
DATA_READ = 0x40000040


def make_pe(
    sections: list[Section] | None = None,
    imports: list[ImportRef] | None = None,
    entry_point: int = 0x1000,
    data_directories: dict | None = None,
    characteristics: int = 0x0022,
    dll_characteristics: int = 0x0140,
    timestamp: int = 0x60000000,
) -> PEInfo:
    section_list = sections if sections is not None else [Section(".text", 0x200, 0x1000, 0x200, 0x200, CODE)]
    return PEInfo(
        machine=0x14C,
        number_of_sections=len(section_list),
        time_date_stamp=timestamp,
        characteristics=characteristics,
        optional_magic=0x10B,
        linker_version="14.0",
        entry_point=entry_point,
        image_base=0x400000,
        subsystem=3,
        dll_characteristics=dll_characteristics,
        size_of_image=0x4000,
        size_of_headers=0x200,
        file_alignment=0x200,
        section_alignment=0x1000,
        checksum=0,
        number_of_rva_and_sizes=16,
        data_directories=data_directories if data_directories is not None else {1: (0x1000, 40)},
        sections=section_list,
        imports=imports if imports is not None else [ImportRef("KERNEL32.dll", "ExitProcess") for _ in range(12)],
    )


def titles(findings: list[Finding]) -> list[str]:
    return [finding.title for finding in findings]


def test_clean_binary_has_no_weighted_findings():
    findings = check_all(make_pe(), [], overall_entropy=6.0)
    assert score(findings) == 0
    assert verdict(findings) == "no notable packer or obfuscation indicators"
    assert all(finding.severity == INFO for finding in findings)


def test_high_overall_entropy_is_high_severity():
    findings = check_all(make_pe(), [], overall_entropy=7.5)
    high = [finding for finding in findings if finding.severity == HIGH]
    assert any("entropy" in finding.title.lower() for finding in high)


def test_medium_overall_entropy():
    findings = check_all(make_pe(), [], overall_entropy=7.0)
    assert any(
        finding.severity == MEDIUM and "entropy" in finding.title.lower()
        for finding in findings
    )


def test_high_entropy_section():
    sections = [Section(".text", 0x100, 0x1000, 0x4000, 0x200, CODE, entropy=7.6)]
    findings = check_all(make_pe(sections=sections), [], overall_entropy=6.0)
    assert any("close to random data" in title for title in titles(findings))
    assert any(finding.severity == HIGH for finding in findings)


def test_high_entropy_section_below_threshold_is_not_flagged():
    sections = [Section(".rsrc", 0x100, 0x1000, 0x4000, 0x200, DATA_READ, entropy=6.9)]
    findings = check_all(make_pe(sections=sections), [], overall_entropy=6.0)
    assert not any("entropy" in title.lower() for title in titles(findings))


def test_tiny_section_is_ignored_for_entropy():
    sections = [Section(".text", 0x100, 0x1000, 0x100, 0x200, CODE, entropy=8.0)]
    findings = check_all(make_pe(sections=sections), [], overall_entropy=6.0)
    assert not any("close to random data" in title for title in titles(findings))


def test_packer_section_names():
    sections = [
        Section("UPX0", 0x1000, 0x1000, 0, 0, CODE),
        Section("UPX1", 0x1000, 0x2000, 0x1000, 0x200, CODE_WRITE),
    ]
    findings = check_all(make_pe(sections=sections), [], overall_entropy=7.6)
    assert "Section names match known packers" in titles(findings)
    assert "Non standard section names" in titles(findings)


def test_plain_dot_sections_are_not_flagged_as_unusual():
    sections = [
        Section(".text", 0x200, 0x1000, 0x200, 0x200, CODE),
        Section(".debug_info", 0x200, 0x2000, 0x200, 0x400, DATA_READ),
    ]
    findings = check_all(make_pe(sections=sections), [], overall_entropy=6.0)
    assert "Non standard section names" not in titles(findings)


def test_undotted_section_names_are_flagged():
    sections = [Section("CODE", 0x200, 0x1000, 0x200, 0x200, CODE)]
    findings = check_all(make_pe(sections=sections), [], overall_entropy=6.0)
    assert "Non standard section names" in titles(findings)


def test_writable_executable_section():
    sections = [Section(".text", 0x200, 0x1000, 0x200, 0x200, CODE_WRITE)]
    findings = check_all(make_pe(sections=sections), [], overall_entropy=5.0)
    assert any("writable and executable" in title for title in titles(findings))


def test_no_imports_with_import_directory():
    findings = check_all(make_pe(imports=[]), [], overall_entropy=6.0)
    assert "Import directory is present but empty" in titles(findings)


def test_no_import_directory_at_all():
    findings = check_all(
        make_pe(imports=[], data_directories={}), [], overall_entropy=6.0
    )
    assert "No import table" in titles(findings)


def test_small_import_table():
    imports = [ImportRef("KERNEL32.dll", "ExitProcess")]
    findings = check_all(make_pe(imports=imports), [], overall_entropy=6.0)
    assert "Only 1 imported function" in titles(findings)


def test_suspicious_imports_are_listed():
    imports = [ImportRef("KERNEL32.dll", name) for name in (
        "VirtualAlloc", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
        "LoadLibraryA", "GetProcAddress",
    )]
    findings = check_all(make_pe(imports=imports), [], overall_entropy=6.0)
    entry = next(finding for finding in findings if "behaviourally interesting" in finding.title)
    assert "VirtualAlloc" in entry.detail


def test_entry_point_outside_sections():
    findings = check_all(make_pe(entry_point=0x9000), [], overall_entropy=6.0)
    assert any("outside every section" in title for title in titles(findings))


def test_entry_point_in_high_entropy_last_section():
    sections = [
        Section(".text", 0x200, 0x1000, 0x200, 0x200, CODE, entropy=5.0),
        Section(".data", 0x2000, 0x2000, 0x2000, 0x400, CODE_WRITE, entropy=7.5),
    ]
    findings = check_all(make_pe(sections=sections, entry_point=0x2000), [], overall_entropy=7.0)
    assert any("last, high entropy section" in title for title in titles(findings))


def test_overlay_high_entropy_is_medium():
    findings = check_all(
        make_pe(), [], overall_entropy=6.0, overlay_size=4096, overlay_entropy=7.4
    )
    overlay = next(finding for finding in findings if "Overlay data" in finding.title)
    assert overlay.severity == MEDIUM


def test_overlay_low_entropy_is_low():
    findings = check_all(
        make_pe(), [], overall_entropy=6.0, overlay_size=4096, overlay_entropy=3.0
    )
    overlay = next(finding for finding in findings if "Overlay data" in finding.title)
    assert overlay.severity == LOW


def test_overlay_with_symbol_table_is_informational():
    pe = make_pe()
    pe.pointer_to_symbol_table = 0x1000
    pe.number_of_symbols = 10
    findings = check_all(
        pe,
        [],
        overall_entropy=6.0,
        overlay_size=8192,
        overlay_entropy=3.0,
        overlay_start=0x800,
        file_size=0x3000,
    )
    overlay = next(finding for finding in findings if "Overlay data" in finding.title)
    assert overlay.severity == INFO
    assert "COFF symbol table" in overlay.detail


def test_section_expanding_in_memory():
    sections = [Section(".data", 0x20000, 0x1000, 0x200, 0x200, CODE)]
    findings = check_all(make_pe(sections=sections), [], overall_entropy=6.0)
    assert any("expands heavily in memory" in title for title in titles(findings))


def test_tls_directory_is_noted():
    findings = check_all(
        make_pe(data_directories={1: (0x1000, 40), 9: (0x3000, 0x18)}), [], overall_entropy=6.0
    )
    assert "TLS directory present" in titles(findings)


def test_signature_presence():
    signed = check_all(
        make_pe(data_directories={1: (0x1000, 40), 4: (0x3000, 0x200)}), [], overall_entropy=6.0
    )
    assert "Authenticode certificate table present" in titles(signed)
    unsigned = check_all(make_pe(), [], overall_entropy=6.0)
    assert "No Authenticode signature" in titles(unsigned)


def test_string_findings():
    strings = [
        ExtractedString(0x10, "http://example.test/gate.php", "ascii"),
        ExtractedString(0x40, "C:\\build\\agent.pdb", "ascii"),
    ]
    findings = check_all(make_pe(), strings, overall_entropy=6.0)
    assert any("behaviour keywords" in title for title in titles(findings))
    assert "Debug path left in the binary" in titles(findings)


def test_findings_are_sorted_by_severity():
    findings = check_all(make_pe(entry_point=0x9000, imports=[]), [], overall_entropy=7.6)
    order = {HIGH: 0, MEDIUM: 1, LOW: 2, INFO: 3}
    severities = [order[finding.severity] for finding in findings]
    assert severities == sorted(severities)


@pytest.mark.parametrize(
    "findings,expected",
    [
        ([], "no notable"),
        ([Finding(LOW, "a", "b")], "a few weak"),
        ([Finding(MEDIUM, "a", "b")] * 2, "several indicators"),
        ([Finding(HIGH, "a", "b"), Finding(HIGH, "b", "c")], "strong indicators"),
    ],
)
def test_verdict_thresholds(findings, expected):
    assert verdict(findings).startswith(expected)
