# This code adds a new section to the PE file\
import os
import pefile
from math import ceil
from enum import IntEnum


class PERM(IntEnum):
    CODE = 0x00000020       # IMAGE_SCN_CNT_CODE
    INITIALIZED_DATA = 0x00000040  # IMAGE_SCN_CNT_INITIALIZED_DATA
    UNINITIALIZED_DATA = 0x00000080  # IMAGE_SCN_CNT_UNINITIALIZED_DATA
    DISCARDABLE = 0x02000000  # IMAGE_SCN_CNT_DISCARDABLE
    LOCKED = 0x04000000         # IMAGE_SCN_MEM_LOCKED
    PRELOAD = 0x08000000        # IMAGE_SCN_MEM_PRELOAD
    NONCACHED = 0x04000000      # IMAGE_SCN_MEM_NOT_CACHED
    NONPAGED = 0x08000000       # IMAGE_SCN_MEM_NOT_PAGED
    SHARED = 0x10000000     # IMAGE_SCN_MEM_SHARED
    EXECUTE = 0x20000000        # IMAGE_SCN_MEM_EXECUTE
    READ = 0x40000000       # IMAGE_SCN_MEM_READ
    WRITE = 0x80000000      # IMAGE_SCN_MEM_WRITE


def btoi(data: bytes) -> int:
    return int.from_bytes(data, byteorder="little")


def itob4(data: int) -> bytes:
    return data.to_bytes(4, byteorder="little")


def itob2(data: int) -> bytes:
    return data.to_bytes(2, byteorder="little")


def to_extend(data: bytes) -> int:
    pe = pefile.PE(data=data)
    section_table_offset = pe.DOS_HEADER.e_lfanew + 0x18 + pe.FILE_HEADER.SizeOfOptionalHeader
    section_count = pe.FILE_HEADER.NumberOfSections

    if pe.OPTIONAL_HEADER.SizeOfHeaders < section_table_offset + (section_count + 1) * 0x28:
        return pe.OPTIONAL_HEADER.FileAlignment * ceil(0x28 / pe.OPTIONAL_HEADER.FileAlignment)
    else:
        return 0


def extend_section_table(data: bytes, extend_size: int) -> bytes:
    pe = pefile.PE(data=data)

    if extend_size <= 0:
        return data

    # Check if the extend size has valid alignment
    if extend_size % pe.OPTIONAL_HEADER.FileAlignment != 0:
        raise ValueError("Invalid extend size")

    # Extend the size of the section table
    prev_soh = pe.OPTIONAL_HEADER.SizeOfHeaders
    pe.OPTIONAL_HEADER.SizeOfHeaders += extend_size
    for section in pe.sections:
        section.PointerToRawData += extend_size

    data = pe.write()
    data = data[:prev_soh] + bytes(extend_size) + data[prev_soh:]
    return data


# Adds a new dummy section as the last section of the PE file
def add_section(data: bytes, section_name: str, section_data: bytes = None, section_perm: int = PERM.READ | PERM.EXECUTE) -> bytes:
    data = extend_section_table(data, to_extend(data))
    data = bytearray(data)

    # Get PE header offset
    pe_header_offset = btoi(data[0x3C:0x40])  # e_lfanew
    if data[pe_header_offset : pe_header_offset + 4] != b"PE\x00\x00":
        raise ValueError("Invalid PE header offset")

    # Get alignments
    va_alignment = btoi(data[pe_header_offset + 0x38 : pe_header_offset + 0x3C])  # SectionAlignment
    file_alignment = btoi(data[pe_header_offset + 0x3C : pe_header_offset + 0x40])  # FileAlignment

    # Create empty section if no data is given
    if section_data is None:
        section_data = bytes(va_alignment)

    # Get section size
    section_size = ceil(len(section_data) / file_alignment) * file_alignment

    # Get Section Table offset
    section_count = btoi(data[pe_header_offset + 0x6 : pe_header_offset + 0x8])  # NumberOfSections
    size_of_optional_header = btoi(data[pe_header_offset + 0x14 : pe_header_offset + 0x16])  # SizeOfOptionalHeader
    section_table_offset = pe_header_offset + 0x18 + size_of_optional_header

    # Get addresses of last section
    last_section_offset = section_table_offset + (section_count - 1) * 0x28
    last_section_vas = btoi(data[last_section_offset + 0x8 : last_section_offset + 0xC])  # VirtualSize
    last_section_va = btoi(data[last_section_offset + 0xC : last_section_offset + 0x10])  # VirtualAddress
    last_section_ras = btoi(data[last_section_offset + 0x10 : last_section_offset + 0x14])  # SizeOfRawData
    last_section_ptra = btoi(data[last_section_offset + 0x14 : last_section_offset + 0x18])  # PointerToRawData

    # Construct new section header
    section_raw = bytearray(40)
    section_raw[0:8] = section_name.encode("utf-8")[:8].ljust(8, b"\x00")  # Name
    section_raw[8:12] = itob4(len(section_data))  # VirtualSize
    section_raw[12:16] = itob4(ceil((last_section_va + last_section_vas) / va_alignment) * va_alignment)  # VirtualAddress
    section_raw[16:20] = itob4(section_size)  # SizeOfRawData
    section_raw[20:24] = itob4(last_section_ptra + last_section_ras)  # PointerToRawData
    section_raw[24:28] = itob4(0)  # PointerToRelocations
    section_raw[28:32] = itob4(0)  # PointerToLinenumbers
    section_raw[32:34] = itob2(0)  # NumberOfRelocations
    section_raw[34:36] = itob2(0)  # NumberOfLinenumbers

    # if section_perm < 0 or section_perm > 15:
    #     raise ValueError("Invalid Section Permission")

    # section_raw[36:40] = itob4(0x20 | section_perm << 28)  # Characteristics
    section_raw[36:40] = itob4(0x20 | section_perm)  # Characteristics

    # Add new section header to PE section table
    section_offset = section_table_offset + (section_count * 0x28)
    # if data[section_offset : section_offset + 0x28].count(b"\x00") != 0x28:
        # raise ValueError("Invalid PE section table")
    data[section_offset : section_offset + 0x28] = section_raw

    # Add new section data to PE data
    section_data = section_data[:section_size].ljust(section_size, b"\x00") if section_data else os.urandom(section_size)
    section_ptra = btoi(section_raw[20:24])
    data = data[:section_ptra] + section_data + data[section_ptra:]

    # Update Image size
    image_size = btoi(data[pe_header_offset + 0x50 : pe_header_offset + 0x54])  # SizeOfImage
    image_size += ceil(section_size / va_alignment) * va_alignment
    data[pe_header_offset + 0x50 : pe_header_offset + 0x54] = itob4(image_size)

    # Update section count
    section_count += 1
    data[pe_header_offset + 0x6 : pe_header_offset + 0x8] = itob2(section_count)

    return data


# Test code
if __name__ == "__main__":

    data = bytearray(open("putty.exe", "rb").read())
    new_data = add_section(data, ".newsection", b"Hello World", PERM.READ | PERM.WRITE | PERM.EXEC)
    open("putty_new.exe", "wb").write(new_data)
