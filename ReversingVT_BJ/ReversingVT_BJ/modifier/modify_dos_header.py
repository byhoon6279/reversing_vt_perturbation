import os

def btoi(data: bytes) -> int:
    return int.from_bytes(data, byteorder="little")


def modify_dos_header(data:bytes) -> bytes:
    data = bytearray(data)

    pe_header_offset = btoi(data[0x3C:0x40])  # e_lfanew
    if data[pe_header_offset : pe_header_offset + 4] != b"PE\x00\x00":
        raise ValueError("Invalid PE header offset")

    # modify ineffectual DOS header bytes
    data[0x2:0x3C] = os.urandom(0x3A)

    # modify DOS stub
    data[0x40:pe_header_offset] = os.urandom(pe_header_offset - 0x40)

    return data


# Test code
if __name__ == "__main__":
    data = open("putty.exe", "rb").read()
    data = modify_dos_header(data)
    open("fake.exe", "wb").write(data)


    
