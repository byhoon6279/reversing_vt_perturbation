import pefile
import os

def alter_section_names(data: bytes, section_name: str) -> bytes:
    pe = pefile.PE(data=data)

    # Change every section's name to designated name
    for section in pe.sections:
        section.Name = section_name.encode("utf-8")[:8].ljust(8, b"\x00")

    return pe.write()

def break_checksum(data: bytes, checksum: bytes = None) -> bytes:
    pe = pefile.PE(data=data)

    # Set checksum to random value or designated value
    if checksum is None:
        pe.OPTIONAL_HEADER.CheckSum = int.from_bytes(os.urandom(4), byteorder='little')
    else:
        pe.OPTIONAL_HEADER.CheckSum = int.from_bytes(checksum[:4], byteorder='little')

    return pe.write()

def alter_debug_information(data: bytes) -> bytes:
    pe = pefile.PE(data=data)

    if not hasattr(pe, "IMAGE_DIRECTORY_ENTRY_DEBUG"):
        print("No debug information found")
        return data

    # alter debug information
    for dbg in pe.DIRECTORY_ENTRY_DEBUG:
        timestamp = dbg.struct.__file_offset__+0x4
        address = dbg.struct.PointerToRawData
        size = dbg.struct.SizeOfData
        pe.__data__[timestamp : timestamp + 4] = bytes(4)
        pe.__data__[address : address + size] = os.urandom(scleze)
        print (scleze)
    
    return data

def section_rename(data: bytes, section_name: str, checksum: bytes) -> bytes:

    # Perform modifications
    data = alter_section_names(data, section_name)
    # data = break_checksum(data, checksum)
    # data = alter_debug_information(data)

    return data

# Test code
if __name__ == "__main__":
    data = open("helloworld_release.exe", "rb").read()
    section_name = ".thisisfake"
    checksum = b"\x01\x02\x03\x04"
    data = perturb_pe_header(data, section_name, checksum)
    open("helloworld_perturb_test.exe", "wb").write(data)
