"""CLI behaviour, exit codes and file output."""

from __future__ import annotations

import json

import pytest

from re_ai import __version__
from re_ai.cli import main


def write_sample(tmp_path, data) -> str:
    target = tmp_path / "sample.exe"
    target.write_bytes(data)
    return str(target)


def test_cli_writes_report_and_json(tmp_path, synthetic_pe_bytes, capsys):
    source = write_sample(tmp_path, synthetic_pe_bytes)
    report = tmp_path / "report.md"
    findings = tmp_path / "findings.json"

    code = main(["--file", source, "--out", str(report), "--json", str(findings)])

    assert code == 0
    text = report.read_text(encoding="utf-8")
    assert "# Static analysis: sample.exe" in text
    assert "## Imports" in text
    assert "KERNEL32.dll" in text
    payload = json.loads(findings.read_text(encoding="utf-8"))
    assert payload["file"]["name"] == "sample.exe"
    assert payload["pe"]["machine"] == "x86"
    assert "report:" in capsys.readouterr().out


def test_default_output_path(tmp_path, synthetic_pe_bytes):
    source = write_sample(tmp_path, synthetic_pe_bytes)
    code = main(["--file", source, "--quiet"])
    assert code == 0
    assert (tmp_path / "sample.exe.re-ai.md").exists()


def test_report_to_stdout(tmp_path, synthetic_pe_bytes, capsys):
    source = write_sample(tmp_path, synthetic_pe_bytes)
    code = main(["--file", source, "--out", "-", "--quiet"])
    assert code == 0
    assert capsys.readouterr().out.startswith("# Static analysis: sample.exe")


def test_missing_file(tmp_path, capsys):
    code = main(["--file", str(tmp_path / "nope.exe")])
    assert code == 2
    assert "no such file" in capsys.readouterr().err


def test_directory_is_rejected(tmp_path, capsys):
    code = main(["--file", str(tmp_path)])
    assert code == 2
    assert "not a regular file" in capsys.readouterr().err


def test_invalid_min_string_length(tmp_path, synthetic_pe_bytes, capsys):
    source = write_sample(tmp_path, synthetic_pe_bytes)
    code = main(["--file", source, "--min-string-length", "0"])
    assert code == 2
    assert "1 or more" in capsys.readouterr().err


def test_negative_string_limit(tmp_path, synthetic_pe_bytes, capsys):
    source = write_sample(tmp_path, synthetic_pe_bytes)
    code = main(["--file", source, "--strings", "-1"])
    assert code == 2
    assert "0 or more" in capsys.readouterr().err


def test_raw_file_still_reports(tmp_path):
    source = tmp_path / "blob.bin"
    source.write_bytes(b"plain bytes " * 40)
    report = tmp_path / "blob.md"
    code = main(["--file", str(source), "--out", str(report), "--quiet"])
    assert code == 0
    assert "Not a PE file" in report.read_text(encoding="utf-8")


def test_llm_without_key_keeps_the_report(tmp_path, synthetic_pe_bytes, monkeypatch, capsys):
    monkeypatch.delenv("RE_AI_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    source = write_sample(tmp_path, synthetic_pe_bytes)
    report = tmp_path / "report.md"

    code = main(["--file", source, "--out", str(report), "--llm", "--quiet"])

    assert code == 1
    assert "API key" in capsys.readouterr().err
    assert "did not run" in report.read_text(encoding="utf-8")


def test_llm_with_a_local_endpoint(tmp_path, synthetic_pe_bytes, fake_llm_server, monkeypatch):
    monkeypatch.setenv("RE_AI_BASE_URL", fake_llm_server.base_url)
    monkeypatch.setenv("RE_AI_API_KEY", "test-key")
    source = write_sample(tmp_path, synthetic_pe_bytes)
    report = tmp_path / "report.md"

    code = main(["--file", source, "--out", str(report), "--llm", "--model", "fake-model", "--quiet"])

    assert code == 0
    text = report.read_text(encoding="utf-8")
    assert "console program" in text
    assert "fake-model" in text
    assert len(fake_llm_server.requests) == 1


@pytest.mark.parametrize("extra", [["--version"]])
def test_version_flag(extra, capsys):
    with pytest.raises(SystemExit) as excinfo:
        main(extra)
    assert excinfo.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_accepts_files_with_no_extension(tmp_path, synthetic_pe_bytes):
    source = tmp_path / "binary"
    source.write_bytes(synthetic_pe_bytes)
    assert main(["--file", str(source), "--quiet"]) == 0
    report = tmp_path / "binary.re-ai.md"
    assert report.exists()
    assert report.read_text(encoding="utf-8").startswith("# Static analysis: binary")
