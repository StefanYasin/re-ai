"""String extraction tests."""

from __future__ import annotations

from re_ai.strings import (
    ExtractedString,
    default_strings_floor,
    extract_ascii_strings,
    extract_strings,
    extract_utf16_strings,
    interesting_strings,
)


def test_ascii_runs_min_length():
    data = b"\x00abc\x00abcd\x00"
    values = [item.value for item in extract_ascii_strings(data, min_length=4)]
    assert values == ["abcd"]


def test_offsets_are_byte_positions():
    data = b"\x01\x02HELLO\x00"
    found = extract_ascii_strings(data, min_length=4)
    assert len(found) == 1
    assert found[0].offset == 2
    assert found[0].encoding == "ascii"


def test_run_at_end_of_file():
    assert [item.value for item in extract_ascii_strings(b"\x00\x00TRAILING", 4)] == ["TRAILING"]


def test_utf16_detection():
    data = "wide string here".encode("utf-16le")
    found = extract_utf16_strings(data, min_length=4)
    assert len(found) == 1
    assert found[0].value == "wide string here"
    assert found[0].encoding == "utf-16le"


def test_utf16_needs_printable_pairs():
    data = "abc".encode("utf-16le") + b"\x00\x01" + "defg".encode("utf-16le")
    values = [item.value for item in extract_utf16_strings(data, min_length=4)]
    assert values == ["defg"]


def test_utf16_does_not_steal_the_tail_of_an_ascii_run():
    data = b"ALPHA\x00" + "BETA".encode("utf-16le")
    values = sorted(item.value for item in extract_strings(data, min_length=4))
    assert values == ["ALPHA", "BETA"]


def test_extract_strings_is_sorted_by_offset():
    data = b"ALPHA\x00\x00" + "BETA".encode("utf-16le")
    found = extract_strings(data, min_length=4)
    assert [item.offset for item in found] == sorted(item.offset for item in found)
    assert {item.value for item in found} == {"ALPHA", "BETA"}


def test_extract_strings_can_skip_utf16():
    data = "BETA".encode("utf-16le")
    assert extract_strings(data, min_length=4, include_utf16=False) == []


def test_binary_noise_yields_nothing():
    assert extract_strings(bytes(range(1, 32)) * 10, min_length=4) == []


def test_interesting_flag():
    assert ExtractedString(0, "http://x.test/a", "ascii").is_interesting
    assert ExtractedString(0, "VirtualAlloc", "ascii").is_interesting
    assert not ExtractedString(0, "plain sentence", "ascii").is_interesting


def test_interesting_strings_sorted_and_limited():
    strings = [
        ExtractedString(0x30, "http://short.test", "ascii"),
        ExtractedString(0x10, "http://a-much-longer-domain.test/gate.php", "ascii"),
        ExtractedString(0x50, "unrelated", "ascii"),
    ]
    hits = interesting_strings(strings, limit=1)
    assert len(hits) == 1
    assert hits[0].value.startswith("http://a-much-longer")


def test_default_strings_floor_scales():
    assert default_strings_floor(1024) == 4
    assert default_strings_floor(9 * 1024 * 1024) == 6
    assert default_strings_floor(65 * 1024 * 1024) == 8
