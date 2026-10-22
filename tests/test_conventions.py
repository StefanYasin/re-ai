"""Repo level rules: no dash artifacts, MIT licence, README footer, CI."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from re_ai import __version__

ROOT = Path(__file__).resolve().parents[1]
EM_DASH = "\u2014"
EN_DASH = "\u2013"
TEXT_SUFFIXES = {".py", ".md", ".toml", ".yml", ".yaml", ".c", ".cfg", ".txt"}


def repo_text_files() -> list[Path]:
    files = []
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        if any(part in {".git", ".venv", "build", "dist", "__pycache__", ".pytest_cache"} for part in path.parts):
            continue
        if path.suffix.lower() in TEXT_SUFFIXES or path.name in {".gitignore", "LICENSE"}:
            files.append(path)
    return files


@pytest.mark.parametrize("path", repo_text_files(), ids=lambda path: path.name)
def test_no_em_or_en_dashes(path):
    text = path.read_text(encoding="utf-8", errors="replace")
    assert EM_DASH not in text, f"{path} contains an em dash"
    assert EN_DASH not in text, f"{path} contains an en dash"


def test_readme_has_the_footer():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "Built by Stefan Yasin" in readme
    assert "https://stefanyasin.github.io/" in readme
    assert "## Install" in readme
    assert "## Usage" in readme


def test_mit_licence():
    licence = (ROOT / "LICENSE").read_text(encoding="utf-8")
    assert licence.startswith("MIT License")
    assert "Stefan Yasin" in licence


def test_version_matches_pyproject():
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'^version = "([^"]+)"', pyproject, re.MULTILINE)
    assert match is not None
    assert match.group(1) == __version__


def test_no_runtime_dependencies():
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    dependencies = re.search(r"^dependencies = \[(.*?)\]", pyproject, re.MULTILINE | re.DOTALL)
    assert dependencies is not None
    assert dependencies.group(1).strip() == ""


def test_ci_workflow_runs_pytest():
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert "pytest" in workflow
    assert "python-version" in workflow
    assert "pull_request" in workflow
