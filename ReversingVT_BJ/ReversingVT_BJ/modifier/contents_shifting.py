import pefile

def gap_sections(data: bytes, gap_size: int = 0x1000) -> bytes:
    data = bytearray(data)
    pe = pefile.PE(data=data)

    # create gap between sections
    for i in range(0, len(pe.sections)):
        offset = pe.sections[i].PointerToRawData + i*gap_size
        raw_data_ptr = pe.sections[i].__file_offset__+0x14

        pe.__data__ = pe.__data__[:offset] + bytearray(gap_size) + pe.__data__[offset:]
        pe.__data__[raw_data_ptr:raw_data_ptr+4] = (pe.sections[i].PointerToRawData + (i+1)*gap_size).to_bytes(4, 'little')
        

    return pe.__data__

def extend_and_shift_sections(data:bytes, shift_size: int = 0x1000) -> bytes:
    data = bytearray(data)
    pe = pefile.PE(data=data)

    # shift sections
    for i in range(0, len(pe.sections)):
        if(i == 0):
            if pe.sections[i].PointerToRawData < pe.OPTIONAL_HEADER.SizeOfHeaders + shift_size:
                raise ValueError("Section {} is too small to shift".format(i))
        else:
            if pe.sections[i].PointerToRawData < pe.sections[i-1].PointerToRawData + pe.sections[i-1].SizeOfRawData + shift_size:
                raise ValueError("Section {} is too small to shift".format(i))
        
        ptra = pe.sections[i].PointerToRawData
        ras = pe.sections[i].SizeOfRawData
        ptra_offset = pe.sections[i].__file_offset__+0x14
        ras_offset = pe.sections[i].__file_offset__+0x10

        # Extend section to gap infront of the section
        # shift contents forward to create space for adverse
        section_data = pe.__data__[ptra:pe.sections[i].PointerToRawData + pe.sections[i].SizeOfRawData]

        pe.__data__[ptra_offset:ptra_offset+4] = (ptra - shift_size).to_bytes(4, 'little')
        pe.__data__[ras_offset:ras_offset+4] = (ras + shift_size).to_bytes(4, 'little')

        pe.__data__[ptra- shift_size:ptra-shift_size+ras] = section_data
        pe.__data__[ptra-shift_size+ras:ptra+ras] = bytearray(shift_size)

    return pe.__data__

# Test code
if __name__ == "__main__":
    data = open("putty.exe", "rb").read()
    data = gap_sections(data)
    data = extend_and_shift_sections(data)
    open("fake.exe", "wb").write(data)
