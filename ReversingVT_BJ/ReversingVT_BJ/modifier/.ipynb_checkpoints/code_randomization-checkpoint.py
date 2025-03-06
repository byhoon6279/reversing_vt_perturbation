from iced_x86 import *
from typing import Dict, Sequence
from types import ModuleType
from pwn import *
import re

def btoi(data: bytes) -> int:
    return int.from_bytes(data, byteorder="little")


def itob4(data: int) -> bytes:
    return data.to_bytes(4, byteorder="little")


def itob2(data: int) -> bytes:
    return data.to_bytes(2, byteorder="little")

def create_enum_dict(module: ModuleType) -> Dict[int, str]:
    return {module.__dict__[key]:key for key in module.__dict__ if isinstance(module.__dict__[key], int)}

REGISTER_TO_STRING: Dict[Register_, str] = create_enum_dict(Register)
def register_to_string(value: Register_) -> str:
    s = REGISTER_TO_STRING.get(value)
    if s is None:
        return str(value) + " /*Register enum*/"
    return s

MNEMONIC_TO_STRING: Dict[Mnemonic_, str] = create_enum_dict(Mnemonic)
def mnemonic_to_string(value: Mnemonic_) -> str:
    s = MNEMONIC_TO_STRING.get(value)
    if s is None:
        return str(value) + " /*Mnemonic enum*/"
    return s

def count_valid_bytecode(bytecode: bytes, min: int = 0x20, max: int = 0x30) -> int:
    md = Cs(CS_ARCH_X86, CS_MODE_32)

    result = 0    
    for insn in md.disasm(bytecode, 0x1000):
        result += insn.size
        if result >= min and result < max:
            return result

    raise ValueError("Failed to count valid Bytecodes")
    return 0

def make_push_pop(reg: bytes, opcode: int) -> bytes:
    insts = []
    if reg == 'eax':
        insts.append(Instruction.create_reg(opcode, Register.EAX))
    if reg == 'ebx':
        insts.append(Instruction.create_reg(opcode, Register.EBX))
    if reg == 'ecx':
        insts.append(Instruction.create_reg(opcode, Register.ECX))
    if reg == 'edx':
        insts.append(Instruction.create_reg(opcode, Register.EDX))
    if reg == 'edi':
        insts.append(Instruction.create_reg(opcode, Register.EDI))
    if reg == 'esi':
        insts.append(Instruction.create_reg(opcode, Register.ESI))
    if reg == 'esp':
        insts.append(Instruction.create_reg(opcode, Register.ESP))
    if reg == 'ebp':
        insts.append(Instruction.create_reg(opcode, Register.EBP))

    encoder = BlockEncoder(32)
    encoder.add_many(insts)
    return encoder.encode(0)

def code_randomization(data: bytes) -> bytes:
    """
    Replace instruction sequence with semantically equivalent one 
    
    xor -> sub
    test -> or
    mov -> push
    nop -> jmp

    Args:
        data: Raw PE Binary bytes

    Reference:
        ASM-Obfuscator: https://github.com/c4ln/ASM-Obfuscator

    Returns:
        PE binary bytes with code randomization applied
    """

    registerSet = ["eax", "ebx", "ecx", "edx", "edi", "esi", "ebp"]
    equivalentInstructionSet = [
        {"xor", "sub"},
        # ?? ec ?? ?? ?? [xor]
        # => 
        # ?? f4 ?? ?? ?? [sub]

        {"test", "or"},
        # f7 c4 ?? ?? ?? ?? [test]
        # =>
        # ?? cc ?? ?? ?? ?? [or]
        
        {"mov", "push"},
        # bc ?? ?? ?? ?? [mov]

        {"nop", "push edi, pop edi"}
    ]

    data = bytearray(data)

    # Get PE header offset
    pe_header_offset = btoi(data[0x3C:0x40])  # e_lfanew
    if data[pe_header_offset : pe_header_offset + 4] != b"PE\x00\x00":
        raise ValueError("Invalid PE header offset")

    # Disable IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE
    data[0xd6 : 0xd8] = itob2(0x8100)

    PE_image_base = btoi(data[pe_header_offset + 0x34: pe_header_offset + 0x38])

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

        if section_permission & 0b10:
            found = True
            print(f"Executable Section Name : {section_name.decode()}")

            section_info = {}
            section_info["VirtualSize"] = btoi(data[cur_section_header + 0x8 : cur_section_header + 0xc])
            section_info["PointerToRawData"] = btoi(data[cur_section_header + 0x14 : cur_section_header + 0x18])
            executable_section_list.append(section_info)

    if found == False:
        raise ValueError("Failed to find Executable Section")

    base = PE_image_base

    for target_section in executable_section_list:
        section_data_offset = target_section["PointerToRawData"]
        section_data_size = target_section["VirtualSize"]

        section_data = data[section_data_offset : section_data_offset + section_data_size]

        decoder = Decoder(32, section_data, ip=0x0)
        formatter = Formatter(FormatterSyntax.MASM) # or INTEL
        info_factory = InstructionInfoFactory()

        target_native_code_set = []
        nop_list = []

        ip = 0x0
        for instr in decoder:
            disasm = formatter.format(instr)
            op_code = instr.op_code()
            info = info_factory.info(instr)

            # Not Implement
            # if op_code.op_code_string == 'test':
            # if cur_op == 'XOR' or cur_op == 'test':
            #     value["inst"] = disasm
            #     value["opcode"] = cur_op
            #     value["offset"] = instr.ip


            cur_op = mnemonic_to_string(instr.mnemonic)

            if cur_op == 'NOP':
                nop_list.append(instr.ip)

            elif cur_op == 'MOV':
                op_set = re.split(r',| ', disasm)
                if op_set[1] in registerSet and op_set[2] in registerSet:
                    value = {}
                    value["inst"] = disasm
                    value['opcode'] = cur_op
                    value["op1"] = op_set[1]    # pop
                    value["op2"] = op_set[2]    # push 
                    value["offset"] = instr.ip
                    target_native_code_set.append(value)

            ip += instr.code_size

        used_nop = []
        for i in range(0, len(nop_list) - 1):
            if nop_list[i] in used_nop:
                continue

            if nop_list[i+1] - nop_list[i] == 1:
                # print('hit')
                nop_list[i]
                reg = random.choice(registerSet)
                inst = b''
                inst += make_push_pop(reg, Code.PUSH_R32)
                inst += make_push_pop(reg, Code.POP_R32)
                
                data[section_data_offset + nop_list[i] : section_data_offset + nop_list[i] + 2] = inst
                used_nop.append(nop_list[i+1])

        
        for native_value in target_native_code_set:
            # Not Implement
            # if native_value["opcode"] == 'XOR': # --> sub
            
            if native_value["opcode"] == 'MOV':
                new_inst = b''
                new_inst += make_push_pop(native_value["op2"], Code.PUSH_R32)
                new_inst += make_push_pop(native_value["op1"], Code.POP_R32)
                
                ip = native_value["offset"]
                data[section_data_offset + ip : section_data_offset + ip + 2] = new_inst


    return data

if __name__ == '__main__':
    data = bytearray(open("test/putty.exe", "rb").read())
    new_data = code_randomization(data)
    open("test/putty_new.exe", "wb").write(new_data)