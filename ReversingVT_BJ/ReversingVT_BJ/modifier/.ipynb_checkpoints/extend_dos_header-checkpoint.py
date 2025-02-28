import os
import pefile
from math import ceil

def extend_dos_stub(data: bytes, code: bytes):
    pe = pefile.PE(data=data)

    # Check Range
    # TODO: Support longer code by adjusting base
    if len(code) > 0xE00:
        raise ValueError("Unsupported stub length")

    # Modify DOS stub
    stub_length = pe.DOS_HEADER.e_lfanew - 0x40
    new_stub_length = ceil((len(code) - stub_length)/pe.OPTIONAL_HEADER.FileAlignment)*pe.OPTIONAL_HEADER.FileAlignment + stub_length
   
    # Update offsets
    pe.DOS_HEADER.e_lfanew += (new_stub_length - stub_length)
    pe.OPTIONAL_HEADER.SizeOfHeaders += (new_stub_length - stub_length)
    for section in pe.sections:
        section.PointerToRawData += (new_stub_length - stub_length)

    code = code + os.urandom(new_stub_length - len(code))
    
    data = pe.write()
    data = data[:0x40] + code + data[0x40 + stub_length:]
    return data


# Test code
if __name__ == "__main__":
    data = open("putty.exe", "rb").read()
    code = b"\x90" * (0xA00)
    data = extend_dos_stub(data, code)
    open("fake.exe", "wb").write(data)