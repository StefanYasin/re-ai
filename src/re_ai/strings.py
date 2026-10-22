"""Printable string extraction.

Two passes: ASCII runs and UTF-16LE runs. UTF-16 matters on Windows binaries
because wide strings are everywhere and a plain ASCII pass misses them.
"""

from __future__ import annotations

from dataclasses import dataclass

DEFAULT_MIN_LENGTH = 4

INTERESTING_TERMS = (
    "http://",
    "https://",
    "ftp://",
    "cmd.exe",
    "powershell",
    "wscript",
    "rundll32",
    "regsvr32",
    "schtasks",
    "mshta",
    ".onion",
    "VirtualAlloc",
    "VirtualProtect",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "LoadLibrary",
    "GetProcAddress",
    "IsDebuggerPresent",
    "OutputDebugString",
    "SELECT ",
    "INSERT INTO",
    "password",
    "token=",
    "api_key",
    "BEGIN RSA",
    "BEGIN PRIVATE KEY",
    "Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run",
    ".pdb",
)


@dataclass(frozen=True)
class ExtractedString:
    offset: int
    value: str
    encoding: str

    @property
    def is_interesting(self) -> bool:
        lowered = self.value.lower()
        return any(term.lower() in lowered for term in INTERESTING_TERMS)

    def __str__(self) -> str:
        return self.value


def _is_printable_ascii(byte: int) -> bool:
    return 0x20 <= byte <= 0x7E


def extract_ascii_strings(data: bytes, min_length: int = DEFAULT_MIN_LENGTH) -> list[ExtractedString]:
    strings: list[ExtractedString] = []
    start = 0
    length = 0
    for index, byte in enumerate(data):
        if _is_printable_ascii(byte) or byte == 0x09:
            if length == 0:
                start = index
            length += 1
            continue
        if length >= min_length:
            strings.append(
                ExtractedString(
                    offset=start,
                    value=data[start : start + length].decode("ascii", errors="replace"),
                    encoding="ascii",
                )
            )
        length = 0
    if length >= min_length:
        strings.append(
            ExtractedString(
                offset=start,
                value=data[start : start + length].decode("ascii", errors="replace"),
                encoding="ascii",
            )
        )
    return strings


def extract_utf16_strings(data: bytes, min_length: int = DEFAULT_MIN_LENGTH) -> list[ExtractedString]:
    strings: list[ExtractedString] = []
    index = 0
    total = len(data)
    while index + 1 < total:
        # A UTF-16LE printable character is an ASCII byte followed by a NUL.
        if _is_printable_ascii(data[index]) and data[index + 1] == 0x00:
            if index > 0 and _is_printable_ascii(data[index - 1]):
                # This pair is the tail of an ASCII run plus its terminator, not
                # the start of a wide string. Skip it instead of producing a
                # spliced value like "ABETA".
                index += 1
                continue
            start = index
            chars: list[str] = []
            while (
                index + 1 < total
                and _is_printable_ascii(data[index])
                and data[index + 1] == 0x00
            ):
                chars.append(chr(data[index]))
                index += 2
            if len(chars) >= min_length:
                strings.append(
                    ExtractedString(offset=start, value="".join(chars), encoding="utf-16le")
                )
            continue
        index += 1
    return strings


def extract_strings(
    data: bytes, min_length: int = DEFAULT_MIN_LENGTH, include_utf16: bool = True
) -> list[ExtractedString]:
    """Return printable strings ordered by file offset."""
    found = extract_ascii_strings(data, min_length)
    if include_utf16:
        found.extend(extract_utf16_strings(data, min_length))
    found.sort(key=lambda item: item.offset)
    return found


def interesting_strings(strings: list[ExtractedString], limit: int = 40) -> list[ExtractedString]:
    """Strings that usually say something about behaviour, longest first."""
    hits = [item for item in strings if item.is_interesting]
    hits.sort(key=lambda item: (-len(item.value), item.offset))
    unique: list[ExtractedString] = []
    seen: set[str] = set()
    for item in hits:
        if item.value in seen:
            continue
        seen.add(item.value)
        unique.append(item)
    return unique[:limit]


def default_strings_floor(size: int) -> int:
    """Pick a minimum length so very large files do not drown the report."""
    if size > 64 * 1024 * 1024:
        return 8
    if size > 8 * 1024 * 1024:
        return 6
    return DEFAULT_MIN_LENGTH
