def btoi(data: bytes) -> int:
    return int.from_bytes(data, byteorder="little")


def itob4(data: int) -> bytes:
    return data.to_bytes(4, byteorder="little")


def itob2(data: int) -> bytes:
    return data.to_bytes(2, byteorder="little")


def change_entry_point(data: bytes, new_entry_point: int) -> bytes:
    """
    Sets the entry-point to a new executable section that jumps back to the original code

    Args:
        data: Raw PE Binary bytes
        new_entry_point: int Value that will be write

    Returns:
        PE binary bytes with changed entry-point
    """
    data = bytearray(data)

    # Get PE header offset
    pe_header_offset = btoi(data[0x3C:0x40])  # e_lfanew
    if data[pe_header_offset : pe_header_offset + 4] != b"PE\x00\x00":
        raise ValueError("Invalid PE header offset")

    # Find Original Entry Point in PE Header 
    AddressOfEntryPoint_offset = pe_header_offset + 0x28
    original_entry_point = btoi(data[AddressOfEntryPoint_offset : AddressOfEntryPoint_offset + 4])
    print(f"[+] Original Entry Point : {original_entry_point:#x}")

    # change value of AddressOfEntryPoint 
    print(f"[+] Change value of AddressOfEntryPoint to {new_entry_point:#x} in PE Header. . .")
    data[AddressOfEntryPoint_offset : AddressOfEntryPoint_offset + 4] = itob4(new_entry_point)

    return data

if __name__ == '__main__':
    data = bytearray(open("test/sample.exe", "rb").read())
    new_data = change_entry_point(data, 0xdeadbeef)
    open("test/changed_sample.exe", "wb").write(new_data)
