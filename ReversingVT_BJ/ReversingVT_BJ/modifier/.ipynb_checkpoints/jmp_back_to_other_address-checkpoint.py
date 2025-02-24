from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from add_section import * 
from iced_x86 import *
from overlay_append import *
from pwn import *

def btoi(data: bytes) -> int:
    return int.from_bytes(data, byteorder="little")


def itob4(data: int) -> bytes:
    return data.to_bytes(4, byteorder="little")


def itob2(data: int) -> bytes:
    return data.to_bytes(2, byteorder="little")

def get_overlay_address(data: bytearray) -> int:
    # Get PE header offset
    pe_header_offset = btoi(data[0x3C:0x40])  # e_lfanew
    if data[pe_header_offset : pe_header_offset + 4] != b"PE\x00\x00":
        raise ValueError("Invalid PE header offset")

    section_header_start_offset = pe_header_offset + 0xf8
    total_number_of_section = btoi(data[pe_header_offset + 0x6 : pe_header_offset + 0x8])
    
    highest_PointerToRawData = 0 
    highest_SizeOfRawData = 0
    for i in range(total_number_of_section):
        cur_section_header = section_header_start_offset + i * section_header_size
        section_name = bytes(data[cur_section_header : cur_section_header + 0x8])

        cur_SizeOfRawData = btoi(data[cur_section_header + 0x10 : cur_section_header + 0x14])
        cur_PointerToRawData = btoi(data[cur_section_header + 0x14 : cur_section_header + 0x18])

        if cur_SizeOfRawData + cur_PointerToRawData > len(data):
            continue
        
        if cur_SizeOfRawData + cur_PointerToRawData > highest_PointerToRawData + highest_SizeOfRawData:
            highest_PointerToRawData = cur_PointerToRawData
            highest_SizeOfRawData = cur_SizeOfRawData
    
    if len(data) > highest_PointerToRawData + highest_SizeOfRawData:
        return highest_PointerToRawData + highest_SizeOfRawData

    return None


def count_valid_bytecode(bytecode: bytes, min: int = 0x20, max: int = 0x30) -> int:
    md = Cs(CS_ARCH_X86, CS_MODE_32)

    result = 0    
    for insn in md.disasm(bytecode, 0x1000):
        result += insn.size
        if result >= min and result < max:
            return result

    raise ValueError("Failed to count valid Bytecodes")
    return 0

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
        cur_section_name = bytes(data[cur_section_header : cur_section_header + 0x8])

        if cur_section_name.replace(b'\x00', b'') == section_name:
            return cur_section_header
    
    return 0


def make_assemble_jmp(jmp_target):
    '''
    0:  68 ef be ad de          push   0xdeadbeef
    5:  c3                      ret
    '''

    asm_bytes = b"\x68"
    asm_bytes += itob4(jmp_target)
    asm_bytes += b"\xc3"
    return asm_bytes
    
def make_assemble_call(call_target):
    '''
    0:  57                      push   edi
    1:  68 ef be ad de          push   0xdeadbeef
    6:  5f                      pop    edi
    7:  ff d7                   call   edi
    9:  5f                      pop    edi
    '''

    asm_bytes = b"\x57" # push edi
    asm_bytes += b"\x68" # push
    asm_bytes += itob4(call_target)
    asm_bytes += b"\x5f" # pop edi 
    asm_bytes += b'\xff\xd7' # call edi
    asm_bytes += b'\x5f' # pop edi
    return asm_bytes


# def make_assemble_recovery(hook_info, back_address):
#     '''
#     push edi
#     push esi 
#     mov edi, [hook_info]
#     mov esi, [hook_info + 4]

#     mov [back_address], edi
#     mov [back_address+4], esi

#     pop esi
#     pop edi
#     jmp back_address
#     '''

#     encoder = BlockEncoder(32)
#     ins = []
#     ins.append(Instruction.create_reg(Code.PUSH_R32, Register.EDI))
#     ins.append(Instruction.create_reg(Code.PUSH_R32, Register.ESI))
    
#     # ins.append(Instruction.create_reg_mem(Code.MOV_R32_RM32, Register.EDI, MemoryOperand(Register.EIP, displ=hook_info - 18)))
#     # ins.append(Instruction.create_reg_mem(Code.MOV_R32_RM32, Register.ESI, MemoryOperand(Register.EIP, displ=hook_info - 14)))
    
#     # ins.append(Instruction.create_mem_reg(Code.MOV_RM32_R32, MemoryOperand(Register.NONE, displ=back_address), Register.EDI))
#     # ins.append(Instruction.create_mem_reg(Code.MOV_RM32_R32, MemoryOperand(Register.NONE, displ=back_address + 4), Register.ESI))

#     ins.append(Instruction.create_reg(Code.POP_R32, Register.ESI))
#     ins.append(Instruction.create_reg(Code.POP_R32, Register.EDI))

#     # # mov [back_address], edi
#     # block += Instruction.create_mov_rm32_imm32(MemoryOperand(Register.RIP, back_address, 4), Register.RDI)

#     encoder.add_many(ins)
#     encoded_bytes = encoder.encode(0)
#     return encoded_bytes


def jmp_back_to_other_address(data: bytes, hook_target_VA: int, overlay_address: int) -> bytes:
    """
    Overlay에 추가한 address에 jump하고 기존 code로 다시 jump
    ==> Hooker

    1. memcpy "ptr [hook_target_VA]" to .ccc[i]. (size : 0x10)
    2. Overwrite "jmp .ccc[i]" to "ptr [hook_target_VA]"
    3. jmp .ccc[i]
    - In .ccc[i]
        1. Call overlay_address
        2. receovery original_function code [ memcpy(back_address, backup_code, 0x10) ]
        3. jmp back_address
    
    
    Args:
        data: Raw PE Binary bytes
        hook_target_VA: Target function address to hook
        overlay_address: overlay address containing the address of the code to be executed

    Returns:
        PE binary bytes with jmp back to other address applied
    """

    
    data = bytearray(data)

    # Get PE header offset
    pe_header_offset = btoi(data[0x3C:0x40])  # e_lfanew
    if data[pe_header_offset : pe_header_offset + 4] != b"PE\x00\x00":
        raise ValueError("Invalid PE header offset")

    # Disable IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE
    data[0xd6 : 0xd8] = itob2(0x8100)

    # Find default dummy section or Create Dummy Header
    hook_section_header = search_section_header_by_name(data, b".ccc")
    if hook_section_header == 0:
        data = add_section(data, ".ccc", b"\x00" * 0x1000, PERM.READ | PERM.EXEC)

        res = search_section_header_by_name(data, b".ccc")
        try:
            if res == 0:
                raise ValueError("Failed to Add Section")
            else:
                hook_section_header = res
        except ValueError as e:
            return data

    else:
        print("[+] Found Dummy section ['.ccc']")

    RVA__hook_section = btoi(data[hook_section_header + 0xc : hook_section_header + 0x10])

    # Prepare to get raw data pointer of [hook_target_VA]
    PE_image_base = btoi(data[pe_header_offset + 0x34: pe_header_offset + 0x38])
    try:
        text_section_header = search_section_header_by_name(data, b'.text')
        if text_section_header == 0:
            raise ValueError("Failed to Find .text section")
    except ValueError as e:
        return data
    
    RVA__text_section = btoi(data[text_section_header + 0xc : text_section_header + 0x10])
    PointerToRawData_text_section = btoi(data[text_section_header + 0x14 : text_section_header + 0x18])

    # Get Target Address in Overlay
    hook_code_VA = btoi(data[overlay_address : overlay_address + 4])
    hook_target_RawPointer = hook_target_VA - (PE_image_base + RVA__text_section) + PointerToRawData_text_section

    print(f"[+] Hook {hook_target_VA:#x} to {hook_code_VA:#x}")

    # Prepare
    hook_info_size = 0x28
    backup_code_size = count_valid_bytecode(data[PointerToRawData_text_section : PointerToRawData_text_section + 0x100], 0x6, 0x10)
    hook_table_RawPointer = btoi(data[hook_section_header + 0x14 : hook_section_header + 0x18])
    total_hook_info_cnt = btoi(data[hook_table_RawPointer : hook_table_RawPointer + 0x4])
    data[hook_table_RawPointer : hook_table_RawPointer + 0x4] = itob4(total_hook_info_cnt + 1)
    current_hook_info_VA = PE_image_base + RVA__hook_section + 0x8 + total_hook_info_cnt * hook_info_size
    print(f"[+] hook_info count already exists : {total_hook_info_cnt:#x}")
    print(f"[+] backup_code_size : {backup_code_size:#x}")

    # Copy backup data to hook_info
    backup_data = data[hook_target_RawPointer : hook_target_RawPointer + backup_code_size]
    current_hook_info_RawPointer = hook_table_RawPointer + 0x8 + total_hook_info_cnt * hook_info_size
    data[current_hook_info_RawPointer + 0x10 : current_hook_info_RawPointer + 0x20] = backup_data.rjust(0x10, b'\x90')

    # Overwrite 'call hook_code_VA' to hook_info.inst
    # b'\xe8' + itob4(hook_code_VA - 5)
    call_hook_code_asm = make_assemble_call(hook_code_VA)
    data[current_hook_info_RawPointer : current_hook_info_RawPointer + 0x10] = call_hook_code_asm.rjust(0x10, b'\x90')

    # Ovewrite 'jmp hook_info[i].inst' to ptr [hook_target_VA]
    hooking_asm = make_assemble_jmp(current_hook_info_VA) 
    data[hook_target_RawPointer : hook_target_RawPointer + backup_code_size] = hooking_asm.rjust(backup_code_size, b'\x90')

    # Recovery Assembler
    recovery_asm = make_assemble_jmp(hook_target_VA + backup_code_size)
    data[current_hook_info_RawPointer + 0x20 : current_hook_info_RawPointer + 0x28] = recovery_asm.rjust(0x8, b'\x90')
        
    print(f"[+] Recovery asm injected size : {len(recovery_asm):#x}")

    ''' 
    jmp val
    nop
    . . .
    nop

    val = PE_image_base + RVA__hook_section + 0x4(dummy_section.total_hook_info_cnt)
    + total_hook_info_cnt * hook_info_size + 0x4(hook_info.backup_code)

    '''


    '''
    hook_info {
        byte[0x10] inst [call target_function]
        byte[0x10] backup_code
        byte[0x8] jmp hook_address
    }

    hook_table  {
        byte[0x4] total_hook_info_cnt
        byte[0x4] dummy
        hook_info[] hook_info
    }
    '''
    
    return data

if __name__ == '__main__':
    data = bytearray(open("test/putty.exe", "rb").read())
    data = overlay_append_dummy(data, itob4(0x40105c))
    overlay_addr = 0x115120

    print(f"target overlay = {hex(overlay_addr)}")
    new_data = jmp_back_to_other_address(data, 0x401000, overlay_addr)
    open("test/putty_new.exe", "wb").write(new_data)