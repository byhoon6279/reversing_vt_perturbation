from iced_x86 import *
import os
import random

def btoi(data: bytes) -> int:
    return int.from_bytes(data, byteorder="little")


def itob4(data: int) -> bytes:
    return data.to_bytes(4, byteorder="little")


def itob2(data: int) -> bytes:
    return data.to_bytes(2, byteorder="little")

def random_draw(level: int) -> bool:    return random.randint(0, level) == 0

def nop_insertion(data: bytes, optimization_level: int) -> bytes:
    """
    nop insertion with optimization_level [Range(0~3)]
    
    Args:
        data: Raw PE Binary bytes
        optimization_level: level of optimization [0~3]
            0 == optimization with 100%
            1 == optimization with 50% 
            2 == optimization with 33%
            3 == optimization with 25%

    Returns:
        PE binary bytes with nop insertion applied
    """

    data = bytearray(data)

    # Get PE header offset
    pe_header_offset = btoi(data[0x3C:0x40])  # e_lfanew
    if data[pe_header_offset : pe_header_offset + 4] != b"PE\x00\x00":
        raise ValueError("Invalid PE header offset")

    # Disable IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE
    data[0xd6 : 0xd8] = itob2(0x8100)
    
    section_header_start_offset = pe_header_offset + 0xf8
    total_number_of_section = btoi(data[pe_header_offset + 0x6 : pe_header_offset + 0x8])
    print(f"total number of section : {total_number_of_section:#x}")

    section_header_size = 0x28
    executable_section_list = []

    found = False
    for i in range(total_number_of_section):
        cur_section_header = section_header_start_offset + i * section_header_size
        section_name = bytes(data[cur_section_header : cur_section_header + 0x8])
        characteristics = btoi(data[cur_section_header + 0x24 : cur_section_header + 0x28])
        section_permission = characteristics >> 28

        if section_name.startswith(b'.text'):
            found = True
            print(f"Executable Section Name : {section_name.decode()}")

            section_info = {}
            section_info["VirtualSize"] = btoi(data[cur_section_header + 0x8 : cur_section_header + 0xc])
            section_info["PointerToRawData"] = btoi(data[cur_section_header + 0x14 : cur_section_header + 0x18])
            executable_section_list.append(section_info)

    if found == False:
        raise ValueError("Failed to find Executable Section")

    for target_section in executable_section_list:
        section_data_offset = target_section["PointerToRawData"]
        section_data_size = target_section["VirtualSize"]

        section_data = data[section_data_offset : section_data_offset + section_data_size]

        decoder = Decoder(32, section_data, ip=0x0)
        formatter = Formatter(FormatterSyntax.MASM) # or INTEL

        ip = 0x0
        for instr in decoder:
            offsets = decoder.get_constant_offsets(instr)

            disasm = formatter.format(instr)
            if disasm == 'int 3':
                if random_draw(optimization_level) == True:
                    data[section_data_offset + instr.ip] = 0x90

            ip += instr.code_size
        
    return data

if __name__ == '__main__':
    data = bytearray(open("test/putty.exe", "rb").read())
    new_data = nop_insertion(data, 2)
    open("test/putty_new.exe", "wb").write(new_data)