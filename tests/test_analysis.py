"""End to end analysis of bytes and files."""

from __future__ import annotations

import hashlib

import pe_builder
from re_ai.analysis import Analysis, analyze_bytes, analyze_file


def test_pe_analysis_matches_the_bytes(synthetic_pe_bytes):
    analysis = analyze_bytes(synthetic_pe_bytes, name="fixture.exe", path="C:/tmp/fixture.exe")
    assert analysis.kind == "pe"
    assert analysis.size == len(synthetic_pe_bytes)
    assert analysis.sha256 == hashlib.sha256(synthetic_pe_bytes).hexdigest()
    assert analysis.md5 == hashlib.md5(synthetic_pe_bytes).hexdigest()
    assert analysis.pe is not None
    assert analysis.pe.import_dlls == ["KERNEL32.dll"]
    assert analysis.strings_min_length == 4
    assert any("fixture marker" in item.value for item in analysis.strings)
    assert 0.0 <= analysis.overall_entropy <= 8.0
    assert analysis.generated_at.endswith("Z")
    assert analysis.verdict


def test_section_entropy_is_filled_in(synthetic_pe_bytes):
    analysis = analyze_bytes(synthetic_pe_bytes)
    section = analysis.pe.sections[0]
    raw = synthetic_pe_bytes[section.raw_pointer : section.raw_pointer + section.raw_size]
    from re_ai.entropy import shannon_entropy

    assert section.entropy == shannon_entropy(raw)
    assert section.entropy > 0


def test_no_overlay_by_default(synthetic_pe_bytes):
    analysis = analyze_bytes(synthetic_pe_bytes)
    assert analysis.overlay_size == 0
    assert analysis.overlay_entropy == 0.0


def test_overlay_is_detected(synthetic_pe_bytes):
    payload = bytes(range(256)) * 8
    analysis = analyze_bytes(synthetic_pe_bytes + payload)
    assert analysis.overlay_offset == len(synthetic_pe_bytes)
    assert analysis.overlay_size == len(payload)
    assert analysis.overlay_entropy > 7.9


def test_non_pe_is_handled_as_raw():
    analysis = analyze_bytes(b"just text, not a binary " * 20, name="notes.bin")
    assert analysis.kind == "raw"
    assert analysis.pe is None
    assert analysis.pe_error is None
    assert [finding.title for finding in analysis.findings] == ["Not a PE file"]
    assert analysis.risk_score == 0


def test_broken_pe_is_reported_without_crashing():
    import struct

    broken = bytearray(pe_builder.build_minimal_pe())
    # Keep the PE signature but write an optional header magic nobody uses.
    struct.pack_into("<H", broken, 0x80 + 24, 0x107)
    analysis = analyze_bytes(bytes(broken))
    assert analysis.kind == "raw"
    assert analysis.pe is None
    assert analysis.pe_error is not None
    assert "optional header magic" in analysis.pe_error
    assert analysis.findings == []
    assert analysis.strings != []


def test_to_dict_shape(synthetic_pe_bytes):
    payload = analyze_bytes(synthetic_pe_bytes, name="fixture.exe").to_dict()
    assert payload["tool"] == "re-ai"
    assert payload["file"]["name"] == "fixture.exe"
    assert payload["pe"]["sections"][0]["name"] == ".text"
    assert payload["pe"]["imports"][0]["dll"] == "KERNEL32.dll"
    assert payload["strings"]["total"] >= 1
    assert isinstance(payload["findings"], list)
    assert "verdict" in payload


def test_strings_floor_can_be_forced():
    analysis = analyze_bytes(b"\x00ab\x00abcd\x00", strings_min=6)
    assert analysis.strings_min_length == 6
    assert analysis.strings == []


def test_analyze_file(tmp_path, synthetic_pe_bytes):
    target = tmp_path / "sample.exe"
    target.write_bytes(synthetic_pe_bytes)
    analysis = analyze_file(target)
    assert isinstance(analysis, Analysis)
    assert analysis.name == "sample.exe"
    assert analysis.path == str(target.resolve())
    assert analysis.kind == "pe"
