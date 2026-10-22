"""Turn a file into everything the report needs.

``analyze_bytes`` is the single entry point: it hashes the input, parses the PE
headers when the file is one, extracts strings, fills in per section entropy and
runs the heuristics.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .entropy import chunk_entropies, shannon_entropy
from .heuristics import Finding, check_all, score, verdict
from .pe import PEError, PEInfo, is_pe, parse_pe
from .strings import ExtractedString, default_strings_floor, extract_strings


@dataclass
class Analysis:
    name: str
    path: str
    size: int
    sha256: str
    md5: str
    kind: str
    pe: PEInfo | None = None
    strings: list[ExtractedString] = field(default_factory=list)
    strings_min_length: int = 4
    overall_entropy: float = 0.0
    chunk_entropy_mean: float = 0.0
    chunk_entropy_max: float = 0.0
    chunk_entropy_hot_ratio: float = 0.0
    overlay_offset: int = 0
    overlay_size: int = 0
    overlay_entropy: float = 0.0
    findings: list[Finding] = field(default_factory=list)
    pe_error: str | None = None
    generated_at: str = ""
    tool_version: str = __version__

    @property
    def verdict(self) -> str:
        return verdict(self.findings)

    @property
    def risk_score(self) -> int:
        return score(self.findings)

    @property
    def finding_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for finding in self.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts

    def to_dict(self) -> dict:
        pe = self.pe
        return {
            "tool": "re-ai",
            "version": self.tool_version,
            "generated_at": self.generated_at,
            "file": {
                "name": self.name,
                "path": self.path,
                "size": self.size,
                "sha256": self.sha256,
                "md5": self.md5,
                "kind": self.kind,
            },
            "pe": None
            if pe is None
            else {
                "machine": pe.machine_name,
                "is_64bit": pe.is_64bit,
                "is_dll": pe.is_dll,
                "subsystem": pe.subsystem_name,
                "entry_point": hex(pe.entry_point),
                "image_base": hex(pe.image_base),
                "linker_version": pe.linker_version,
                "timestamp": pe.time_date_stamp,
                "sections": [
                    {
                        "name": section.name,
                        "virtual_address": hex(section.virtual_address),
                        "virtual_size": section.virtual_size,
                        "raw_size": section.raw_size,
                        "permissions": section.permissions,
                        "entropy": round(section.entropy, 4),
                    }
                    for section in pe.sections
                ],
                "imports": [
                    {"dll": ref.dll, "name": ref.name, "ordinal": ref.ordinal}
                    for ref in pe.imports
                ],
                "import_error": pe.import_error,
                "signed": pe.has_signature,
            },
            "strings": {
                "total": len(self.strings),
                "min_length": self.strings_min_length,
                "interesting": [item.value for item in self.strings if item.is_interesting][:40],
            },
            "entropy": {
                "overall": round(self.overall_entropy, 4),
                "chunk_mean": round(self.chunk_entropy_mean, 4),
                "chunk_max": round(self.chunk_entropy_max, 4),
                "overlay_size": self.overlay_size,
                "overlay_entropy": round(self.overlay_entropy, 4),
            },
            "findings": [
                {"severity": finding.severity, "title": finding.title, "detail": finding.detail}
                for finding in self.findings
            ],
            "score": self.risk_score,
            "verdict": self.verdict,
        }


def _overlay(data: bytes, pe: PEInfo) -> tuple[int, int, float]:
    end = pe.size_of_headers
    for section in pe.sections:
        if section.raw_size:
            end = max(end, section.raw_pointer + section.raw_size)
    if end >= len(data):
        return end, 0, 0.0
    blob = data[end:]
    return end, len(blob), shannon_entropy(blob)


def analyze_bytes(
    data: bytes,
    name: str = "<memory>",
    path: str = "<memory>",
    strings_min: int | None = None,
    include_utf16: bool = True,
) -> Analysis:
    """Analyze a blob and return an :class:`Analysis`."""
    min_length = strings_min if strings_min is not None else default_strings_floor(len(data))
    analysis = Analysis(
        name=name,
        path=path,
        size=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
        md5=hashlib.md5(data).hexdigest(),
        kind="raw",
        strings_min_length=min_length,
        generated_at=datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    )

    analysis.strings = extract_strings(data, min_length, include_utf16=include_utf16)
    analysis.overall_entropy = shannon_entropy(data)
    chunks = chunk_entropies(data, 1024)
    if chunks:
        values = [value for _, value in chunks]
        analysis.chunk_entropy_mean = sum(values) / len(values)
        analysis.chunk_entropy_max = max(values)
        analysis.chunk_entropy_hot_ratio = sum(1 for value in values if value >= 7.0) / len(values)

    if is_pe(data):
        try:
            analysis.pe = parse_pe(data)
            analysis.kind = "pe"
        except PEError as exc:
            analysis.pe_error = str(exc)

    if analysis.pe is not None:
        for section in analysis.pe.sections:
            if section.raw_size:
                start = section.raw_pointer
                blob = data[start : start + section.raw_size]
                section.entropy = shannon_entropy(blob)
        analysis.overlay_offset, analysis.overlay_size, analysis.overlay_entropy = _overlay(
            data, analysis.pe
        )
        analysis.findings = check_all(
            analysis.pe,
            analysis.strings,
            analysis.overall_entropy,
            analysis.overlay_size,
            analysis.overlay_entropy,
            analysis.overlay_offset,
            analysis.size,
        )
    elif analysis.pe_error is None:
        analysis.findings = [
            Finding(
                "info",
                "Not a PE file",
                "No MZ and PE signature was found, so only strings and entropy "
                "were collected.",
            )
        ]

    return analysis


def analyze_file(path: str | Path, strings_min: int | None = None) -> Analysis:
    file_path = Path(path)
    data = file_path.read_bytes()
    return analyze_bytes(
        data,
        name=file_path.name,
        path=str(file_path.resolve()),
        strings_min=strings_min,
    )
