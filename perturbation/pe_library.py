from pwn import *
from iced_x86 import *
import pefile
import string
import random
import os

def assembler(data: list, bitness: int = 64) -> bytes:
    encoder = BlockEncoder(bitness)
    encoder.add_many(data)
    bytes_code = encoder.encode(0x0)
    return bytes_code

def check32(data: bytes) -> bool:
    pe = pefile.PE(data=data) 
    if pe.FILE_HEADER.Machine == 0x14c:
        return True
    else:
        return False

def btoi(data: bytes) -> int:
    return int.from_bytes(data, byteorder="little")

def itob8(data: int) -> bytes:
    return data.to_bytes(8, byteorder="little")

def itob4(data: int) -> bytes:
    return data.to_bytes(4, byteorder="little")

def itob2(data: int) -> bytes:
    return data.to_bytes(2, byteorder="little")

def get_sections(data: bytes) -> int:
    pe = pefile.PE(data=data)
    return pe.sections

def search_section_header_by_name(data: bytes, section_name: bytes) -> int:
    pe = pefile.PE(data=data)

    for section in pe.sections:
        if section.Name == section_name[:8].ljust(8, b"\x00"):
            return section.get_file_offset()

    return 0

def gen_random_section_name(length: int) -> bytes:
    if length > 7:
        raise ValueError("length must be < 7")
    ascii_characters = string.ascii_letters + string.digits + string.punctuation
    random_ascii_string = ''.join(random.choice(ascii_characters) for _ in range(length))
    return b'.' + random_ascii_string.encode()

def make_assemble_push_imm64(value: int) -> bytes:
    instructions = []
    instructions.append(Instruction.create_i32(Code.PUSHQ_IMM32, 0))
    instructions.append(Instruction.create_mem_i32(Code.MOV_RM32_IMM32, MemoryOperand(Register.RSP, displ=0), value & 0xffffffff))
    instructions.append(Instruction.create_mem_i32(Code.MOV_RM32_IMM32, MemoryOperand(Register.RSP, displ=4), value >> 32))
    return assembler(instructions)

def make_assemble_jmp(data, jmp_target):
    '''
    # 32bit
        0:  68 ef be ad de          push   0xdeadbeef
        5:  c3                      ret

    # 64bit
        0:  6a 00                   push   0x0
        2:  c7 04 24 44 33 22 11    mov    DWORD PTR [rsp],0x11223344
        9:  c7 44 24 04 88 77 66    mov    DWORD PTR [rsp+0x4],0x55667788
        10: 55
        11: c3                      ret
    '''


    if check32(data):
        jmp_asm = b"\x68"
        jmp_asm += itob4(jmp_target)
        jmp_asm += b"\xc3"
        return jmp_asm
    else:
        
        res = b''
        res += make_assemble_push_imm64(jmp_target)
        res += b'\xc3' # ret
        return res 
    
        # jmp_asm = f'''
        # push 0
        # mov DWORD PTR [rsp], {hex(jmp_target & 0xffffffff)}
        # mov DWORD PTR [rsp + 0x4], {hex(jmp_target >> 32)}
        # ret
        # '''
        # return asm(jmp_asm, arch='amd64')

def make_assemble_call(data, call_target):
    '''
    # 32bit
        0:  50                      push   eax
        1:  68 ef be ad de          push   0xdeadbeef
        6:  58                      pop    eax
        7:  ff d0                   call   eax
        9:  58                      pop    eax


    # 64bit
        0:  57                      push   rax
        1:  48 bf 88 77 66 55 44    movabs rax,0x1122334455667788
        8:  33 22 11
        b:  ff d7                   call   rax
        d:  5f                      pop    rax

    '''
    
    if check32(data):
        call_asm = b"\x50" # push eax
        call_asm += b"\x68" # push
        call_asm += itob4(call_target)
        call_asm += b"\x58" # pop eax
        call_asm += b'\xff\xd0' # call eax
        call_asm += b'\x58' # pop eax
        return call_asm
    
    else:
        instructions = []
        instructions.append(Instruction.create_reg(Code.PUSH_R64, Register.RAX))
        instructions.append(Instruction.create_reg_i64(Code.MOV_R64_IMM64, Register.RAX, call_target))
        instructions.append(Instruction.create_reg(Code.CALL_RM64, Register.RAX))
        instructions.append(Instruction.create_reg(Code.POP_R64, Register.RAX))

        res = assembler(instructions)
        return res
    
        # call_asm = f'''
        # push rdi
        # mov rdi, {hex(call_target)}
        # call rdi
        # pop rdi
        # '''
        # return asm(call_asm, arch='amd64')

def get_section_rva(data: bytes, section_name: str) -> int:
    pe = pefile.PE(data=data)
    
    for section in pe.sections:
        if section.Name == section_name[:8].ljust(8, b"\x00"):
            return section.VirtualAddress
        
    return 0

def set_section_rva(data: bytes, section_name: str, new_rva: int) -> bytes:
    pe = pefile.PE(data=data)
    for section in pe.sections:
        if section.Name == section_name[:8].ljust(8, b"\x00"):
            section.VirtualAddress = new_rva
            return pe.write()
    
    return b''

def get_section_offset(data: bytes, section_name: str) -> int:
    pe = pefile.PE(data=data)
    
    for section in pe.sections:
        if section.Name == section_name[:8].ljust(8, b"\x00"):
            return section.PointerToRawData
        
    return 0

def set_section_offset(data: bytes, section_name: str, new_offset: int) -> bytes:
    pe = pefile.PE(data=data)
    for section in pe.sections:
        if section.Name == section_name[:8].ljust(8, b"\x00"):
            section.PointerToRawData = new_offset
            return pe.write()
    
    return b''

def get_entry_point(data: bytes) -> int:
    pe = pefile.PE(data=data)
    res = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    pe.close()
    return res

def set_entry_point(data: bytes, new_entry_point: int) -> bytes:
    pe = pefile.PE(data=data)
    pe.OPTIONAL_HEADER.AddressOfEntryPoint = new_entry_point
    return pe.write()

def disable_ASLR(data: bytes) -> bytes:
    IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE  = 0x40

    pe = pefile.PE(data=data)
    pe.OPTIONAL_HEADER.DllCharacteristics &= ~IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE
    return pe.write()

def get_image_base(data: bytes) -> int:
    pe = pefile.PE(data=data)
    res = pe.OPTIONAL_HEADER.ImageBase
    pe.close()
    return res