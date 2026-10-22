"""Markdown report rendering.

One input, one report. The layout is fixed so reports from different samples
can be diffed against each other.
"""

from __future__ import annotations

from datetime import datetime, timezone

from .analysis import Analysis
from .entropy import describe_entropy
from .pe import DATA_DIRECTORY_NAMES
from .strings import ExtractedString, interesting_strings

FILE_CHARACTERISTICS = {
    0x0001: "relocations stripped",
    0x0002: "executable image",
    0x0020: "large address aware",
    0x0100: "32 bit machine",
    0x0200: "debug stripped",
    0x2000: "DLL",
}

DLL_CHARACTERISTICS = {
    0x0020: "high entropy VA",
    0x0040: "dynamic base (ASLR)",
    0x0080: "force integrity",
    0x0100: "NX compatible (DEP)",
    0x0200: "no isolation",
    0x0400: "no SEH",
    0x0800: "no bind",
    0x1000: "app container",
    0x2000: "WDM driver",
    0x4000: "control flow guard",
    0x8000: "terminate on heap corruption",
}


def _flags(value: int, mapping: dict[int, str]) -> str:
    names = [label for bit, label in mapping.items() if value & bit]
    return ", ".join(names) if names else "none"


def _pe_timestamp(value: int) -> str:
    if not value:
        return "0 (not set)"
    try:
        stamp = datetime.fromtimestamp(value, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return f"{value} (out of range)"
    return stamp.strftime("%Y-%m-%d %H:%M:%S UTC")


def _cell(text: str) -> str:
    """Make a value safe inside a markdown table cell."""
    return str(text).replace("|", "\\|").replace("\n", " ").replace("`", "'")


def _fence(lines: list[str]) -> list[str]:
    fence = "```"
    while any(fence in line for line in lines):
        fence += "`"
    return [fence + "text", *lines, fence]


def _human_size(size: int) -> str:
    if size < 1024:
        return f"{size} bytes"
    for unit in ("KiB", "MiB", "GiB"):
        size_value = size / 1024
        if size_value < 1024:
            return f"{size_value:.1f} {unit} ({size:,} bytes)"
        size = int(size_value)
    return f"{size} bytes"


def _section_table(analysis: Analysis) -> list[str]:
    assert analysis.pe is not None
    lines = [
        "| Section | Virtual address | Virtual size | Raw size | Perm | Entropy |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for section in analysis.pe.sections:
        lines.append(
            "| `{name}` | 0x{va:08x} | 0x{vsize:x} | 0x{raw:x} ({raw:,} bytes) | {perm} | {entropy:.3f} |".format(
                name=_cell(section.name) or "(unnamed)",
                va=section.virtual_address,
                vsize=section.virtual_size,
                raw=section.raw_size,
                perm=section.permissions,
                entropy=section.entropy,
            )
        )
    return lines


def _imports_block(analysis: Analysis) -> list[str]:
    assert analysis.pe is not None
    pe = analysis.pe
    lines: list[str] = []
    if pe.import_error:
        lines.append(f"Import parsing failed: {pe.import_error}")
        lines.append("")
    if not pe.imports:
        lines.append("No imports were recovered.")
        return lines

    by_dll: dict[str, list[str]] = {}
    for ref in pe.imports:
        label = ref.name if ref.name else f"ordinal {ref.ordinal}"
        by_dll.setdefault(ref.dll, []).append(label)

    lines.append(
        f"{len(pe.imports)} imports across {len(by_dll)} DLLs: "
        + ", ".join(f"`{_cell(dll)}` ({len(names)})" for dll, names in by_dll.items())
    )
    lines.append("")
    rows = ["| DLL | Functions |", "| --- | --- |"]
    for dll, names in by_dll.items():
        joined = ", ".join(_cell(name) for name in names[:20])
        if len(names) > 20:
            joined += f", plus {len(names) - 20} more"
        rows.append(f"| `{_cell(dll)}` | {joined} |")
    lines.extend(rows)
    return lines


def _strings_block(analysis: Analysis, limit: int) -> list[str]:
    lines: list[str] = []
    hits = interesting_strings(analysis.strings, limit=limit)
    total = len(analysis.strings)
    lines.append(
        f"{total} printable strings at minimum length {analysis.strings_min_length} "
        f"(ASCII and UTF-16LE)."
    )
    lines.append("")
    if hits:
        lines.append("Strings that match behaviour keywords:")
        lines.append("")
        entries = [f"0x{item.offset:08x}  {item.value[:160]}" for item in hits]
        lines.extend(_fence(entries))
        lines.append("")

    longest = sorted(analysis.strings, key=lambda item: (-len(item.value), item.offset))[:limit]
    if longest:
        lines.append("Longest strings:")
        lines.append("")
        entries = [f"0x{item.offset:08x}  {len(item.value):>4}  {item.value[:160]}" for item in longest]
        lines.extend(_fence(entries))
    return lines


def _finding_table(analysis: Analysis) -> list[str]:
    if not analysis.findings:
        return ["No findings."]
    lines = ["| Severity | Finding | Detail |", "| --- | --- | --- |"]
    for finding in analysis.findings:
        lines.append(
            f"| {finding.severity} | {_cell(finding.title)} | {_cell(finding.detail)} |"
        )
    return lines


def _header_block(analysis: Analysis) -> list[str]:
    pe = analysis.pe
    assert pe is not None
    rows = [
        ("Machine", f"{pe.machine_name} (0x{pe.machine:04x})"),
        ("Format", "PE32+" if pe.is_64bit else "PE32"),
        ("Subsystem", pe.subsystem_name),
        ("Linker version", pe.linker_version),
        ("Image type", "DLL" if pe.is_dll else "executable"),
        ("Entry point", f"0x{pe.entry_point:x}"),
        ("Image base", f"0x{pe.image_base:x}"),
        ("Sections", str(pe.number_of_sections)),
        ("Size of image", f"0x{pe.size_of_image:x}"),
        ("Size of headers", f"0x{pe.size_of_headers:x}"),
        ("File alignment", f"0x{pe.file_alignment:x}"),
        ("Section alignment", f"0x{pe.section_alignment:x}"),
        ("Timestamp", _pe_timestamp(pe.time_date_stamp)),
        ("Checksum", f"0x{pe.checksum:08x}"),
        ("File characteristics", _flags(pe.characteristics, FILE_CHARACTERISTICS)),
        ("DLL characteristics", _flags(pe.dll_characteristics, DLL_CHARACTERISTICS)),
    ]
    lines = ["| Field | Value |", "| --- | --- |"]
    for field_name, value in rows:
        lines.append(f"| {field_name} | {_cell(value)} |")

    present = sorted(pe.data_directories.items())
    if present:
        lines.append("")
        lines.append("Data directories:")
        lines.append("")
        lines.append("| Directory | RVA | Size |")
        lines.append("| --- | --- | --- |")
        for index, (rva, size) in present:
            label = DATA_DIRECTORY_NAMES.get(index, f"index {index}")
            lines.append(f"| {label} | 0x{rva:08x} | 0x{size:x} |")
    return lines


def render_report(
    analysis: Analysis,
    llm_text: str | None = None,
    llm_model: str | None = None,
    llm_error: str | None = None,
    strings_limit: int = 25,
) -> str:
    """Render the full markdown report."""
    lines: list[str] = []
    add = lines.append

    add(f"# Static analysis: {analysis.name}")
    add("")
    add(
        f"`{analysis.path}` | {_human_size(analysis.size)} | "
        f"sha256 `{analysis.sha256}`"
    )
    add("")
    add(
        f"Generated {analysis.generated_at} by re-ai {analysis.tool_version}. "
        "Static inspection only: nothing was executed."
    )
    add("")

    counts = analysis.finding_counts
    add("## Assessment")
    add("")
    add(f"**{analysis.verdict}**")
    add("")
    add(
        f"Score {analysis.risk_score}. Findings: "
        + ", ".join(f"{counts.get(level, 0)} {level}" for level in ("high", "medium", "low", "info"))
        + "."
    )
    add("")
    lines.extend(_finding_table(analysis))
    add("")

    add("## File")
    add("")
    add("| Field | Value |")
    add("| --- | --- |")
    add(f"| Name | {_cell(analysis.name)} |")
    add(f"| Size | {analysis.size:,} bytes |")
    add(f"| Kind | {analysis.kind} |")
    add(f"| SHA256 | `{analysis.sha256}` |")
    add(f"| MD5 | `{analysis.md5}` |")
    add(f"| Entropy | {analysis.overall_entropy:.3f} bits per byte |")
    add("")

    if analysis.pe_error:
        add("## PE headers")
        add("")
        add(f"The file starts like a PE image but could not be parsed: {analysis.pe_error}")
        add("")

    if analysis.pe is not None:
        add("## PE headers")
        add("")
        lines.extend(_header_block(analysis))
        add("")

        add("## Sections")
        add("")
        lines.extend(_section_table(analysis))
        add("")

        add("## Imports")
        add("")
        lines.extend(_imports_block(analysis))
        add("")

    add("## Strings")
    add("")
    lines.extend(_strings_block(analysis, strings_limit))
    add("")

    add("## Entropy")
    add("")
    add(
        f"Whole file: {analysis.overall_entropy:.3f} bits per byte, "
        f"{describe_entropy(analysis.overall_entropy)}."
    )
    add("")
    add(
        f"1 KiB chunks: mean {analysis.chunk_entropy_mean:.3f}, "
        f"max {analysis.chunk_entropy_max:.3f}, "
        f"{analysis.chunk_entropy_hot_ratio * 100:.1f}% of chunks at or above 7.0."
    )
    add("")
    if analysis.overlay_size:
        add(
            f"Overlay starts at 0x{analysis.overlay_offset:x} and is "
            f"{analysis.overlay_size:,} bytes with entropy "
            f"{analysis.overlay_entropy:.3f}."
        )
    else:
        add("No overlay data after the last section.")
    add("")

    add("## Analysis")
    add("")
    if llm_text:
        add(f"Drafted with `{_cell(llm_model or 'unknown model')}` from the facts above.")
        add("")
        add(llm_text.strip())
    elif llm_error:
        add(f"LLM drafting was requested but did not run: {llm_error}")
    else:
        add("LLM drafting is off. Pass `--llm` with `RE_AI_BASE_URL` and `RE_AI_API_KEY` set to add a written analysis.")
    add("")

    add("## Method and limits")
    add("")
    add(
        "Headers are parsed by a small hand written PE reader (stdlib struct only). "
        "Strings are raw printable runs, so they are not tied back to sections. "
        "Entropy and heuristic checks flag patterns, not intent. Nothing here "
        "replaces running the sample in an isolated environment with a debugger."
    )
    add("")
    add("Generated by re-ai.")
    add("")
    return "\n".join(lines)
