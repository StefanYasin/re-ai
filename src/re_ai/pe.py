"""A small PE/COFF reader written against ``struct`` only.

This is deliberately not a full PE library. It reads the DOS header, the COFF
header, the optional header, the section table and the import directory, which
is enough to describe a sample in a report. Every read is bounds checked and
anything unexpected raises :class:`PEError` instead of returning junk.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

IMAGE_FILE_MACHINE_NAMES = {
    0x014C: "x86",
    0x0166: "MIPS R4000",
    0x01C0: "ARM",
    0x01C2: "Thumb",
    0x01C4: "ARMv7",
    0x0200: "IA64",
    0x8664: "x86-64",
    0xAA64: "ARM64",
    0x5032: "RISC-V 32",
    0x5064: "RISC-V 64",
}

SUBSYSTEM_NAMES = {
    1: "native",
    2: "Windows GUI",
    3: "Windows console",
    5: "OS/2 console",
    7: "POSIX console",
    9: "Windows CE",
    10: "EFI application",
    11: "EFI boot service driver",
    12: "EFI runtime driver",
    13: "EFI ROM",
    14: "Xbox",
    16: "Windows boot application",
}

# data directory indexes
DIR_EXPORT = 0
DIR_IMPORT = 1
DIR_RESOURCE = 2
DIR_EXCEPTION = 3
DIR_SECURITY = 4
DIR_BASERELOC = 5
DIR_DEBUG = 6
DIR_TLS = 9
DIR_IAT = 12
DIR_DELAY_IMPORT = 13

DATA_DIRECTORY_NAMES = {
    DIR_EXPORT: "export",
    DIR_IMPORT: "import",
    DIR_RESOURCE: "resource",
    DIR_EXCEPTION: "exception",
    DIR_SECURITY: "security (certificate table)",
    DIR_BASERELOC: "base relocation",
    DIR_DEBUG: "debug",
    7: "architecture",
    8: "global pointer",
    DIR_TLS: "thread local storage",
    10: "load config",
    11: "bound import",
    DIR_IAT: "import address table",
    DIR_DELAY_IMPORT: "delay import",
    14: "COM descriptor",
    15: "reserved",
}

SECTION_CODE = 0x00000020
SECTION_INITIALIZED_DATA = 0x00000040
SECTION_UNINITIALIZED_DATA = 0x00000080
SECTION_DISCARDABLE = 0x02000000
SECTION_NOT_CACHED = 0x04000000
SECTION_NOT_PAGED = 0x08000000
SECTION_SHARED = 0x10000000
SECTION_EXECUTE = 0x20000000
SECTION_READ = 0x40000000
SECTION_WRITE = 0x80000000


class PEError(ValueError):
    """Raised when the input is not a PE file or is truncated."""


def _read(fmt: str, data: bytes, offset: int, what: str) -> tuple:
    size = struct.calcsize(fmt)
    if offset < 0 or offset + size > len(data):
        raise PEError(
            f"{what} at offset 0x{offset:x} needs {size} bytes but the file "
            f"is {len(data)} bytes"
        )
    return struct.unpack_from(fmt, data, offset)


@dataclass
class Section:
    name: str
    virtual_size: int
    virtual_address: int
    raw_size: int
    raw_pointer: int
    characteristics: int
    entropy: float = 0.0

    @property
    def executable(self) -> bool:
        return bool(self.characteristics & SECTION_EXECUTE)

    @property
    def writable(self) -> bool:
        return bool(self.characteristics & SECTION_WRITE)

    @property
    def readable(self) -> bool:
        return bool(self.characteristics & SECTION_READ)

    @property
    def permissions(self) -> str:
        return "".join(
            [
                "r" if self.readable else "-",
                "w" if self.writable else "-",
                "x" if self.executable else "-",
            ]
        )

    @property
    def end_rva(self) -> int:
        return self.virtual_address + max(self.virtual_size, self.raw_size)

    def contains_rva(self, rva: int) -> bool:
        return self.virtual_address <= rva < self.end_rva


@dataclass
class ImportRef:
    dll: str
    name: str | None = None
    ordinal: int | None = None

    def __str__(self) -> str:
        if self.name:
            return f"{self.dll}!{self.name}"
        return f"{self.dll}!#{self.ordinal}"


@dataclass
class PEInfo:
    machine: int
    number_of_sections: int
    time_date_stamp: int
    characteristics: int
    optional_magic: int
    linker_version: str
    entry_point: int
    image_base: int
    subsystem: int
    dll_characteristics: int
    size_of_image: int
    size_of_headers: int
    file_alignment: int
    section_alignment: int
    checksum: int
    number_of_rva_and_sizes: int
    pointer_to_symbol_table: int = 0
    number_of_symbols: int = 0
    size_of_code: int = 0
    size_of_initialized_data: int = 0
    size_of_uninitialized_data: int = 0
    base_of_code: int = 0
    data_directories: dict[int, tuple[int, int]] = field(default_factory=dict)
    sections: list[Section] = field(default_factory=list)
    imports: list[ImportRef] = field(default_factory=list)
    import_error: str | None = None

    @property
    def is_64bit(self) -> bool:
        return self.optional_magic == 0x20B

    @property
    def machine_name(self) -> str:
        return IMAGE_FILE_MACHINE_NAMES.get(self.machine, f"unknown (0x{self.machine:04x})")

    @property
    def subsystem_name(self) -> str:
        return SUBSYSTEM_NAMES.get(self.subsystem, f"unknown ({self.subsystem})")

    @property
    def is_dll(self) -> bool:
        return bool(self.characteristics & 0x2000)

    @property
    def has_signature(self) -> bool:
        security = self.data_directories.get(DIR_SECURITY)
        return bool(security and security[0] and security[1])

    @property
    def import_dlls(self) -> list[str]:
        seen: list[str] = []
        for ref in self.imports:
            if ref.dll not in seen:
                seen.append(ref.dll)
        return seen

    def directory(self, index: int) -> tuple[int, int]:
        return self.data_directories.get(index, (0, 0))

    def section_for_rva(self, rva: int) -> Section | None:
        for section in self.sections:
            if section.contains_rva(rva):
                return section
        return None

    def rva_to_offset(self, rva: int) -> int | None:
        """Map an RVA to a file offset, or ``None`` when it is not backed by data."""
        if rva < self.size_of_headers:
            return rva
        section = self.section_for_rva(rva)
        if section is None:
            return None
        delta = rva - section.virtual_address
        if delta >= section.raw_size:
            return None
        return section.raw_pointer + delta


def _read_cstring(data: bytes, offset: int, limit: int = 512) -> str:
    if offset < 0 or offset >= len(data):
        raise PEError(f"string offset 0x{offset:x} is outside the file")
    end = data.find(b"\x00", offset, min(len(data), offset + limit))
    if end == -1:
        end = min(len(data), offset + limit)
    return data[offset:end].decode("latin-1", errors="replace")


def _coff_string_table(data: bytes, pointer: int, symbol_count: int) -> bytes:
    """Return the COFF string table, or empty bytes when there is none."""
    if not pointer or not symbol_count:
        return b""
    base = pointer + symbol_count * 18
    if base + 4 > len(data):
        return b""
    (size,) = _read("<I", data, base, "COFF string table size")
    if size < 4 or base + size > len(data):
        return b""
    return data[base : base + size]


def _section_name(raw_name: bytes, string_table: bytes) -> str:
    name = raw_name.split(b"\x00", 1)[0].decode("latin-1", errors="replace")
    # Long names are stored as /<offset> into the COFF string table.
    if name.startswith("/") and name[1:].isdigit() and string_table:
        offset = int(name[1:])
        if 0 < offset < len(string_table):
            end = string_table.find(b"\x00", offset)
            if end == -1:
                end = len(string_table)
            resolved = string_table[offset:end].decode("latin-1", errors="replace")
            if resolved:
                return resolved
    return name


def _parse_sections(
    data: bytes, table_offset: int, count: int, string_table: bytes = b""
) -> list[Section]:
    sections: list[Section] = []
    for index in range(count):
        offset = table_offset + index * 40
        raw_name = data[offset : offset + 8]
        (virtual_size, virtual_address, raw_size, raw_pointer) = _read(
            "<IIII", data, offset + 8, f"section {index} header"
        )
        (characteristics,) = _read(
            "<I", data, offset + 36, f"section {index} characteristics"
        )
        name = _section_name(raw_name, string_table)
        sections.append(
            Section(
                name=name,
                virtual_size=virtual_size,
                virtual_address=virtual_address,
                raw_size=raw_size,
                raw_pointer=raw_pointer,
                characteristics=characteristics,
            )
        )
    return sections


def _parse_imports(data: bytes, info: PEInfo) -> list[ImportRef]:
    import_rva, import_size = info.directory(DIR_IMPORT)
    if not import_rva:
        return []

    descriptor_offset = info.rva_to_offset(import_rva)
    if descriptor_offset is None:
        raise PEError(f"import directory RVA 0x{import_rva:x} has no backing data")

    pointer_size = 8 if info.is_64bit else 4
    pointer_fmt = "<Q" if info.is_64bit else "<I"
    ordinal_flag = 1 << (pointer_size * 8 - 1)
    imports: list[ImportRef] = []

    # 4096 descriptors is far beyond anything a real linker emits.
    for index in range(4096):
        offset = descriptor_offset + index * 20
        if offset + 20 > len(data):
            break
        original_first_thunk, _, _, name_rva, first_thunk = _read(
            "<IIIII", data, offset, "import descriptor"
        )
        if not any((original_first_thunk, name_rva, first_thunk)):
            break

        name_offset = info.rva_to_offset(name_rva)
        dll = _read_cstring(data, name_offset) if name_offset is not None else "<unreadable>"

        thunk_rva = original_first_thunk or first_thunk
        thunk_offset = info.rva_to_offset(thunk_rva) if thunk_rva else None
        if thunk_offset is None:
            imports.append(ImportRef(dll=dll, name="<thunks unreadable>"))
            continue

        for thunk_index in range(8192):
            entry_offset = thunk_offset + thunk_index * pointer_size
            if entry_offset + pointer_size > len(data):
                break
            (value,) = _read(pointer_fmt, data, entry_offset, "import thunk")
            if value == 0:
                break
            if value & ordinal_flag:
                imports.append(ImportRef(dll=dll, ordinal=value & 0xFFFF))
                continue
            hint_name_offset = info.rva_to_offset(value & (ordinal_flag - 1))
            if hint_name_offset is None or hint_name_offset + 2 > len(data):
                imports.append(ImportRef(dll=dll, name="<name unreadable>"))
                continue
            imports.append(ImportRef(dll=dll, name=_read_cstring(data, hint_name_offset + 2)))

    return imports


def parse_pe(data: bytes) -> PEInfo:
    """Parse ``data`` as a PE image.

    Raises :class:`PEError` when the signatures are wrong or a header is
    truncated.
    """
    if len(data) < 0x40:
        raise PEError("file is smaller than a DOS header")
    if data[:2] != b"MZ":
        raise PEError("missing MZ signature")

    (e_lfanew,) = _read("<I", data, 0x3C, "e_lfanew")
    if e_lfanew + 4 > len(data) or data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        raise PEError(f"no PE signature at offset 0x{e_lfanew:x}")

    coff_offset = e_lfanew + 4
    (
        machine,
        number_of_sections,
        time_date_stamp,
        pointer_to_symbols,
        number_of_symbols,
        optional_header_size,
        characteristics,
    ) = _read("<HHIIIHH", data, coff_offset, "COFF header")

    if number_of_sections > 96:
        raise PEError(f"implausible section count: {number_of_sections}")

    optional_offset = coff_offset + 20
    (magic,) = _read("<H", data, optional_offset, "optional header magic")
    if magic not in (0x10B, 0x20B):
        raise PEError(f"unknown optional header magic 0x{magic:x}")

    is_64 = magic == 0x20B
    (linker_major, linker_minor, size_of_code, size_of_init, size_of_uninit, entry_point, base_of_code) = _read(
        "<BBIIIII", data, optional_offset + 2, "optional header"
    )
    if is_64:
        (image_base,) = _read("<Q", data, optional_offset + 24, "ImageBase")
    else:
        (image_base,) = _read("<I", data, optional_offset + 28, "ImageBase")
    # SectionAlignment starts right after the pointer sized ImageBase field.
    alignment_offset = optional_offset + 32

    (
        section_alignment,
        file_alignment,
        _os_major,
        _os_minor,
        _image_major,
        _image_minor,
        _subsystem_major,
        _subsystem_minor,
        _win32_version,
        size_of_image,
        size_of_headers,
        checksum,
        subsystem,
        dll_characteristics,
    ) = _read("<IIHHHHHHIIIIHH", data, alignment_offset, "optional header alignment block")

    if is_64:
        number_offset = optional_offset + 108
        directories_offset = optional_offset + 112
    else:
        number_offset = optional_offset + 92
        directories_offset = optional_offset + 96

    (number_of_rva_and_sizes,) = _read("<I", data, number_offset, "NumberOfRvaAndSizes")
    if optional_header_size and directories_offset - optional_offset > optional_header_size:
        raise PEError("optional header is too small to hold the data directories")

    data_directories: dict[int, tuple[int, int]] = {}
    directory_count = min(number_of_rva_and_sizes, 16)
    for index in range(directory_count):
        offset = directories_offset + index * 8
        if offset + 8 > optional_offset + optional_header_size:
            break
        rva, size = _read("<II", data, offset, f"data directory {index}")
        if rva or size:
            data_directories[index] = (rva, size)

    section_table_offset = optional_offset + optional_header_size
    string_table = _coff_string_table(data, pointer_to_symbols, number_of_symbols)
    sections = _parse_sections(data, section_table_offset, number_of_sections, string_table)

    info = PEInfo(
        machine=machine,
        number_of_sections=number_of_sections,
        time_date_stamp=time_date_stamp,
        characteristics=characteristics,
        optional_magic=magic,
        linker_version=f"{linker_major}.{linker_minor}",
        entry_point=entry_point,
        image_base=image_base,
        subsystem=subsystem,
        dll_characteristics=dll_characteristics,
        size_of_image=size_of_image,
        size_of_headers=size_of_headers,
        file_alignment=file_alignment,
        section_alignment=section_alignment,
        checksum=checksum,
        number_of_rva_and_sizes=number_of_rva_and_sizes,
        pointer_to_symbol_table=pointer_to_symbols,
        number_of_symbols=number_of_symbols,
        size_of_code=size_of_code,
        size_of_initialized_data=size_of_init,
        size_of_uninitialized_data=size_of_uninit,
        base_of_code=base_of_code,
        data_directories=data_directories,
        sections=sections,
    )

    try:
        info.imports = _parse_imports(data, info)
    except PEError as exc:
        info.imports = []
        info.import_error = str(exc)

    return info


def is_pe(data: bytes) -> bool:
    """Cheap check used before attempting a full parse."""
    if len(data) < 0x40 or data[:2] != b"MZ":
        return False
    (e_lfanew,) = struct.unpack_from("<I", data, 0x3C)
    return data[e_lfanew : e_lfanew + 4] == b"PE\x00\x00"
