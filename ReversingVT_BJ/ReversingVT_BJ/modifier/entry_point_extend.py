def btoi(data: bytes) -> int:
    return int.from_bytes(data, byteorder="little")


def itob4(data: int) -> bytes:
    return data.to_bytes(4, byteorder="little")


def itob2(data: int) -> bytes:
    return data.to_bytes(2, byteorder="little")


def search_section_header_by_name(data: bytes, section_name: bytes) -> int:
    pe_header_offset = btoi(data[0x3C:0x40])  # e_lfanew
    if data[pe_header_offset : pe_header_offset + 4] != b"PE\x00\x00":
        raise ValueError("Invalid PE header offset")

    section_header_start_offset = pe_header_offset + 0xf8
    total_number_of_section = btoi(data[pe_header_offset + 0x6 : pe_header_offset + 0x8])

    section_header_size = 0x28
    executable_section_list = []

    target = 0
    for i in range(total_number_of_section):
        cur_section_header = section_header_start_offset + i * section_header_size
        section_name = bytes(data[cur_section_header : cur_section_header + 0x8])

        if cur_section_name.replace(b'\x00', b'').decode() == section_name:
            return cur_section_header
    
    return 0

def entry_point_extend(data: bytes, target_section_name: str, rva_value: int, section_offset_value: int) -> bytes:
    """
    Change Section offset, RVA value
    
    Args:
        data: Raw PE Binary bytes
        target_section_name: Name of target section
        rva_value: RVA value of change
        section_offset_value: Section offset value of change

    Returns:
        PE binary bytes with entry point extend applied
    """

    data = bytearray(data)

    # Get PE header offset
    pe_header_offset = btoi(data[0x3C:0x40])  # e_lfanew
    if data[pe_header_offset : pe_header_offset + 4] != b"PE\x00\x00":
        raise ValueError("Invalid PE header offset")

    section_header_start_offset = pe_header_offset + 0xf8
    total_number_of_section = btoi(data[pe_header_offset + 0x6 : pe_header_offset + 0x8])
    print(f"[+] total number of section : {total_number_of_section:#x}")

    section_header_size = 0x28
    target_section_offset = 0x0

    for i in range(total_number_of_section):
        cur_section_header = section_header_start_offset + i * section_header_size
        cur_section_name = bytes(data[cur_section_header : cur_section_header + 0x8])

        print(cur_section_name, target_section_name)
        if cur_section_name.startswith(target_section_name.encode()):
            print(f"[+] '{target_section_name}' Section found")
            target_section_offset = cur_section_header
            break

    if target_section_offset == 0:
        raise ValueError("Failed to find target section")

    section_rva_offset = target_section_offset + 12
    data[section_rva_offset : section_rva_offset + 4] = itob4(rva_value)

    section_rva_offset = target_section_offset + 20
    data[section_rva_offset : section_rva_offset + 4] = itob4(section_offset_value)

    print("[+] Change value of RVA, Section Offset")
    return data

if __name__ == '__main__':
    data = bytearray(open("test/sample.exe", "rb").read())
    new_data = entry_point_extend(data, '.text', 0x1234, 0xdeadbeef)
    open("test/sample_new.exe", "wb").write(new_data)
