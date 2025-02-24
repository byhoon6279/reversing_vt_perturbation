import os

def btoi(data: bytes) -> int:
    return int.from_bytes(data, byteorder="little")


def modify_dos_header(data:bytes) -> bytes:
    data = bytearray(data)

    try:
        pe_header_offset = btoi(data[0x3C:0x40])  # e_lfanew
        if data[pe_header_offset : pe_header_offset + 4] != b"PE\x00\x00":
            raise ValueError("Invalid PE header offset")

        # modify ineffectual DOS header bytes
        data[0x2:0x3C] = os.urandom(0x3A)

        # modify DOS stub (예외 발생 가능성 있는 부분)
        stub_size = pe_header_offset - 0x40
        if stub_size > 0:  
            data[0x40:pe_header_offset] = os.urandom(stub_size)
        else:
            print(f"Warning: DOS stub size is invalid ({stub_size}). Skipping modification.")

    except Exception as e:
        print(f"Warning: {e}. Skipping DOS header modification.")

    return data


# Test code
if __name__ == "__main__":
    data = open("putty.exe", "rb").read()
    data = modify_dos_header(data)
    open("fake.exe", "wb").write(data)


    
