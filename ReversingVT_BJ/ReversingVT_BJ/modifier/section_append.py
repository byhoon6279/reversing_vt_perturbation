import pefile
import os

def section_append_unused(data:bytes) -> bytes:
    data = bytearray(data)
    pe = pefile.PE(data=data)

    # find and fill unused space in sections with random bytes
    for sections in pe.sections:
        if sections.SizeOfRawData > sections.Misc_VirtualSize:
            offset = sections.PointerToRawData + sections.Misc_VirtualSize
            size = sections.SizeOfRawData - sections.Misc_VirtualSize
            pe.__data__[offset : offset + size] = os.urandom(size)

    return data

def section_append_gap(data:bytes) -> bytes:
    data = bytearray(data)
    pe = pefile.PE(data=data)

    # find and fill gap between sections with random bytes
    for i in range(1, len(pe.sections)):
        offset = pe.sections[i-1].PointerToRawData + pe.sections[i-1].SizeOfRawData
        size = pe.sections[i].PointerToRawData - offset
        pe.__data__[offset : offset + size] = os.urandom(size)
    return data

# Test code
if __name__ == "__main__":
    data = open("putty.exe", "rb").read()
    data = section_append_unused(data)
    data = section_append_gap(data)
    open("fake.exe", "wb").write(data)