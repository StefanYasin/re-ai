"""Tests for the hand written PE reader."""

from __future__ import annotations

import struct

import pytest

import pe_builder
from re_ai.pe import (
    PEError,
    _coff_string_table,
    _section_name,
    is_pe,
    parse_pe,
)


def test_synthetic_headers(synthetic_pe_bytes):
    info = parse_pe(synthetic_pe_bytes)
    assert info.machine == 0x14C
    assert info.machine_name == "x86"
    assert info.is_64bit is False
    assert info.is_dll is False
    assert info.subsystem == 3
    assert info.subsystem_name == "Windows console"
    assert info.entry_point == 0x1000
    assert info.image_base == 0x400000
    assert info.linker_version == "14.0"
    assert info.number_of_sections == 1
    assert info.size_of_headers == 0x200
    assert info.file_alignment == 0x200
    assert info.section_alignment == 0x1000
    assert info.size_of_code == 0x200


def test_synthetic_section(synthetic_pe_bytes):
    section = parse_pe(synthetic_pe_bytes).sections[0]
    assert section.name == ".text"
    assert section.virtual_address == 0x1000
    assert section.virtual_size == 0x200
    assert section.raw_pointer == 0x200
    assert section.raw_size == 0x200
    assert section.executable is True
    assert section.writable is False
    assert section.readable is True
    assert section.permissions == "r-x"
    assert section.end_rva == 0x1200
    assert section.contains_rva(0x1010) is True
    assert section.contains_rva(0x1200) is False


def test_synthetic_imports(synthetic_pe_bytes):
    info = parse_pe(synthetic_pe_bytes)
    assert [str(ref) for ref in info.imports] == [
        "KERNEL32.dll!CreateFileA",
        "KERNEL32.dll!ExitProcess",
    ]
    assert info.import_dlls == ["KERNEL32.dll"]
    assert info.import_error is None
    assert info.imports[0].name == "CreateFileA"
    assert info.imports[0].ordinal is None


def test_synthetic_is_64_bit(synthetic_pe_x64):
    info = parse_pe(synthetic_pe_x64)
    assert info.is_64bit is True
    assert info.machine == 0x8664
    assert info.machine_name == "x86-64"
    assert info.image_base == 0x400000
    assert len(info.imports) == 2


def test_rva_to_offset(synthetic_pe_bytes):
    info = parse_pe(synthetic_pe_bytes)
    assert info.rva_to_offset(0x1000) == 0x200
    assert info.rva_to_offset(0x1080) == 0x280
    assert info.rva_to_offset(0x40) == 0x40
    # Inside the section virtual range but past its raw data.
    assert info.rva_to_offset(0x1400) is None
    assert info.rva_to_offset(0x9000) is None
    assert info.section_for_rva(0x1000).name == ".text"
    assert info.section_for_rva(0x9000) is None


def test_data_directories(synthetic_pe_bytes):
    info = parse_pe(synthetic_pe_bytes)
    assert info.directory(1) == (0x1000, 40)
    assert info.directory(12)[0] == 0x1060
    assert info.directory(0) == (0, 0)
    assert info.has_signature is False


def test_dll_name_and_ordinals():
    data = pe_builder.build_minimal_pe(dll_name=b"USER32.dll\x00")
    info = parse_pe(data)
    assert info.import_dlls == ["USER32.dll"]


def test_ordinal_import_is_read_as_ordinal():
    # Flip the high bit of the first thunk entry to make it an ordinal import.
    data = bytearray(pe_builder.build_minimal_pe())
    int_offset = 0x240
    struct.pack_into("<I", data, int_offset, 0x80000000 | 0x1234)
    info = parse_pe(bytes(data))
    assert info.imports[0].ordinal == 0x1234
    assert info.imports[0].name is None
    assert str(info.imports[0]) == "KERNEL32.dll!#4660"


def test_overlay_is_not_part_of_the_image(synthetic_pe_bytes):
    info = parse_pe(synthetic_pe_bytes + b"OVERLAY")
    assert info.sections[0].raw_size == 0x200
    assert info.rva_to_offset(0x1000) == 0x200


def test_rejects_non_pe():
    with pytest.raises(PEError, match="MZ"):
        parse_pe(b"not a pe file at all" + b"\x00" * 64)


def test_rejects_bad_pe_signature():
    data = bytearray(pe_builder.build_minimal_pe())
    data[0x80:0x84] = b"PX\x00\x00"
    with pytest.raises(PEError, match="PE signature"):
        parse_pe(bytes(data))


def test_rejects_truncated_file(synthetic_pe_bytes):
    with pytest.raises(PEError):
        parse_pe(synthetic_pe_bytes[:0x40])


def test_rejects_bad_optional_magic():
    data = bytearray(pe_builder.build_minimal_pe())
    struct.pack_into("<H", data, 0x80 + 24, 0x107)
    with pytest.raises(PEError, match="optional header magic"):
        parse_pe(bytes(data))


def test_is_pe(synthetic_pe_bytes):
    assert is_pe(synthetic_pe_bytes) is True
    assert is_pe(synthetic_pe_bytes + b"tail") is True
    assert is_pe(b"MZ" + b"\x00" * 100) is False
    assert is_pe(b"") is False


def test_compiled_binary_parses(compiled_pe_bytes):
    info = parse_pe(compiled_pe_bytes)
    assert info.machine in (0x14C, 0x8664)
    assert info.number_of_sections >= 1
    assert len(info.sections) == info.number_of_sections
    assert info.entry_point > 0
    assert info.import_error is None
    for ref in info.imports:
        assert ref.dll.lower().endswith(".dll")


def test_long_section_names_resolve_from_the_coff_string_table():
    table = b"\x14\x00\x00\x00" + b".debug_info\x00more\x00"
    assert _section_name(b"/4", table) == ".debug_info"
    assert _section_name(b"/16", table) == "more"
    assert _section_name(b"/999", table) == "/999"
    assert _section_name(b".text", table) == ".text"
    assert _section_name(b"/4", b"") == "/4"


def test_coff_string_table_is_read_from_the_declared_length():
    symbols = b"\x00" * 18
    table = b"\x0c\x00\x00\x00" + b".debug\x00\x00"
    data = b"pad" + symbols + table
    assert _coff_string_table(data, 3, 1) == table
    assert _coff_string_table(data, 0, 1) == b""
    assert _coff_string_table(data, 3, 0) == b""
    assert _coff_string_table(data[:-2], 3, 1) == b""
