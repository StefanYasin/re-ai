"""Report rendering: headings, values and markdown safety."""

from __future__ import annotations

from re_ai.analysis import analyze_bytes
from re_ai.report import render_report

EM_DASH = "\u2014"
EN_DASH = "\u2013"


def test_report_sections(synthetic_pe_bytes):
    analysis = analyze_bytes(synthetic_pe_bytes, name="fixture.exe", path="C:/tmp/fixture.exe")
    report = render_report(analysis)
    for heading in (
        "# Static analysis: fixture.exe",
        "## Assessment",
        "## File",
        "## PE headers",
        "## Sections",
        "## Imports",
        "## Strings",
        "## Entropy",
        "## Analysis",
        "## Method and limits",
    ):
        assert heading in report
    assert analysis.sha256 in report
    assert "KERNEL32.dll" in report
    assert "CreateFileA" in report
    assert ".text" in report
    assert "r-x" in report


def test_report_mentions_llm_being_off(synthetic_pe_bytes):
    report = render_report(analyze_bytes(synthetic_pe_bytes))
    assert "LLM drafting is off" in report


def test_report_includes_llm_text(synthetic_pe_bytes):
    analysis = analyze_bytes(synthetic_pe_bytes)
    report = render_report(analysis, llm_text="## What it appears to do\nA test harness.", llm_model="fake-model")
    assert "A test harness." in report
    assert "`fake-model`" in report


def test_report_includes_llm_error(synthetic_pe_bytes):
    analysis = analyze_bytes(synthetic_pe_bytes)
    report = render_report(analysis, llm_error="no API key found")
    assert "did not run: no API key found" in report


def test_report_has_no_dash_artifacts(synthetic_pe_bytes):
    report = render_report(analyze_bytes(synthetic_pe_bytes, name="fixture.exe"))
    assert EM_DASH not in report
    assert EN_DASH not in report


def test_report_escapes_table_pipes(synthetic_pe_bytes):
    analysis = analyze_bytes(
        synthetic_pe_bytes, name="odd|name`x.exe", path="C:/tmp/odd|name.exe"
    )
    report = render_report(analysis)
    assert "odd\\|name'x.exe" in report


def test_report_handles_raw_files():
    analysis = analyze_bytes(b"plain bytes " * 50, name="blob.bin", path="C:/tmp/blob.bin")
    report = render_report(analysis)
    assert "Not a PE file" in report
    assert "## PE headers" not in report
    assert "## Sections" not in report


def test_report_overlay_line(synthetic_pe_bytes):
    analysis = analyze_bytes(synthetic_pe_bytes + b"\x00" * 512)
    report = render_report(analysis)
    assert "Overlay starts at" in report


def test_report_truncates_long_string_lists(synthetic_pe_bytes):
    report = render_report(analyze_bytes(synthetic_pe_bytes), strings_limit=0)
    assert "Longest strings" not in report
