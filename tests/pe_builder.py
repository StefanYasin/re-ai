"""Build a small but valid PE image in memory.

The synthetic fixture exists so the parser tests never depend on a compiler.
Every offset below is commented because the whole point is to be checkable by
hand against the PE/COFF specification.
"""

from __future__ import annotations

import struct

FILE_ALIGNMENT = 0x200
SECTION_RVA = 0x1000
HEADERS_SIZE = 0x200
SECTION_RAW = 0x200
IMAGE_BASE = 0x400000
PE_OFFSET = 0x80

DLL_NAME = b"KERNEL32.dll\x00"
FUNCTION_NAMES = (b"CreateFileA", b"ExitProcess")


def build_minimal_pe(
    is_64: bool = False,
    functions: tuple[bytes, ...] = FUNCTION_NAMES,
    dll_name: bytes = DLL_NAME,
    overlay: bytes = b"",
    section_name: bytes = b".text",
    section_fill: bytes = b"",
) -> bytes:
    """Return a one section PE with an import table for KERNEL32.dll."""
    optional_size = 240 if is_64 else 224
    header_size = HEADERS_SIZE
    section_raw_offset = header_size
    buf = bytearray(header_size + SECTION_RAW)

    # DOS stub, only the fields the parser reads are meaningful.
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, PE_OFFSET)

    buf[PE_OFFSET : PE_OFFSET + 4] = b"PE\x00\x00"
    coff = PE_OFFSET + 4
    struct.pack_into(
        "<HHIIIHH",
        buf,
        coff,
        0x8664 if is_64 else 0x14C,  # machine
        1,  # number of sections
        0x60000000,  # timestamp
        0,  # pointer to symbol table
        0,  # number of symbols
        optional_size,  # size of optional header
        0x0022,  # executable image, large address aware
    )

    opt = coff + 20
    struct.pack_into("<H", buf, opt, 0x20B if is_64 else 0x10B)
    struct.pack_into("<BB", buf, opt + 2, 14, 0)  # linker 14.0
    struct.pack_into("<III", buf, opt + 4, SECTION_RAW, SECTION_RAW, 0)
    struct.pack_into("<II", buf, opt + 16, SECTION_RVA, SECTION_RVA)
    if is_64:
        struct.pack_into("<Q", buf, opt + 24, IMAGE_BASE)
    else:
        struct.pack_into("<I", buf, opt + 24, 0x2000)  # BaseOfData
        struct.pack_into("<I", buf, opt + 28, IMAGE_BASE)
    struct.pack_into("<II", buf, opt + 32, 0x1000, FILE_ALIGNMENT)
    struct.pack_into("<HHHHHH", buf, opt + 40, 6, 0, 0, 0, 6, 0)
    struct.pack_into("<I", buf, opt + 52, 0)
    struct.pack_into("<III", buf, opt + 56, 0x2000, HEADERS_SIZE, 0)
    struct.pack_into("<HH", buf, opt + 68, 3, 0x0140)  # console, ASLR + DEP
    if is_64:
        struct.pack_into("<QQQQ", buf, opt + 72, 0x100000, 0x1000, 0x100000, 0x1000)
        struct.pack_into("<II", buf, opt + 104, 0, 16)
        dirs = opt + 112
    else:
        struct.pack_into("<IIII", buf, opt + 72, 0x100000, 0x1000, 0x100000, 0x1000)
        struct.pack_into("<II", buf, opt + 88, 0, 16)
        dirs = opt + 96

    # Section layout inside .text, all RVAs relative to SECTION_RVA.
    import_dir_offset = section_raw_offset + 0x000
    int_offset = section_raw_offset + 0x040
    iat_offset = section_raw_offset + 0x060
    dll_name_offset = section_raw_offset + 0x080
    hints_offset = section_raw_offset + 0x100
    marker_offset = section_raw_offset + 0x1C0

    thunk_size = 8 if is_64 else 4
    thunk_fmt = "<Q" if is_64 else "<I"
    ordinal_flag = 1 << (thunk_size * 8 - 1)

    hint_rvas: list[int] = []
    hint_cursor = hints_offset
    for name in functions:
        struct.pack_into("<H", buf, hint_cursor, 0)  # hint
        buf[hint_cursor + 2 : hint_cursor + 2 + len(name) + 1] = name + b"\x00"
        hint_rvas.append(SECTION_RVA + (hint_cursor - section_raw_offset))
        hint_cursor += 2 + len(name) + 1

    struct.pack_into(
        "<IIIII",
        buf,
        import_dir_offset,
        SECTION_RVA + (int_offset - section_raw_offset),  # OriginalFirstThunk
        0,  # TimeDateStamp
        0,  # ForwarderChain
        SECTION_RVA + (dll_name_offset - section_raw_offset),  # Name
        SECTION_RVA + (iat_offset - section_raw_offset),  # FirstThunk
    )
    # Null descriptor terminates the array.
    struct.pack_into("<IIIII", buf, import_dir_offset + 20, 0, 0, 0, 0, 0)

    for index, rva in enumerate(hint_rvas):
        struct.pack_into(thunk_fmt, buf, int_offset + index * thunk_size, rva)
        struct.pack_into(thunk_fmt, buf, iat_offset + index * thunk_size, rva)
    struct.pack_into(thunk_fmt, buf, int_offset + len(hint_rvas) * thunk_size, 0)
    struct.pack_into(thunk_fmt, buf, iat_offset + len(hint_rvas) * thunk_size, 0)

    buf[dll_name_offset : dll_name_offset + len(dll_name)] = dll_name

    marker = b"re-ai fixture marker string"
    buf[marker_offset : marker_offset + len(marker)] = marker

    if section_fill:
        end = min(len(buf), section_raw_offset + len(section_fill))
        buf[section_raw_offset:end] = section_fill[: end - section_raw_offset]

    # Data directories: import table plus IAT.
    struct.pack_into(
        "<II", buf, dirs + 8, SECTION_RVA, 40
    )
    struct.pack_into(
        "<II",
        buf,
        dirs + 12 * 8,
        SECTION_RVA + (iat_offset - section_raw_offset),
        (len(hint_rvas) + 1) * thunk_size,
    )

    # Section header.
    struct.pack_into(
        "<8sIIIIIIHHI",
        buf,
        opt + optional_size,
        section_name,
        SECTION_RAW,  # virtual size
        SECTION_RVA,  # virtual address
        SECTION_RAW,  # size of raw data
        section_raw_offset,  # pointer to raw data
        0,
        0,
        0,
        0,
        0x60000020,  # code, execute, read
    )

    return bytes(buf) + overlay
