import pefile
from iced_x86 import *
from pe_library import *
from typing import Union, Dict, Sequence 
from types import ModuleType
import binascii
from keystone import *
import pandas as pd
import shutil
from common_function import *
import multiprocessing
import capstone
from functools import lru_cache

old_rawPointer = 0
old_nextPointer = 0

@lru_cache(maxsize=None)
def inst_dict_generator(filepath):
    pe = pefile.PE(filepath)
    pe_data = open(filepath, "rb").read()

    # .text 섹션 데이터 가져오기
    text_section = None

    inst_dict={}
    
    #print(pe.sections.Characteristics())
    
    sections_characteristics = [hex(section.Characteristics) for section in pe.sections]
    executable_sections = [
    hex(section.Characteristics) for section in pe.sections
    if section.Characteristics in [0x20000020, 0x60000020, 0x68000020,  0xA0000020, 0xE0000020] ]


    for section in pe.sections:
        #print(section)
#         if (not (section.Name.rstrip(b'\x00').lower().endswith(b'data') or section.Name.rstrip(b'\x00').lower() == b'.rsrc' or section.Name.rstrip(b'\x00').lower() == b'.reloc')) and \
#            ((section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_CNT_CODE']) or \
#             (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_READ']) or \
#             (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE'])) and \
#            ((section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_WRITE']) or 
#             (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE']) or 
#             (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_CNT_INITIALIZED_DATA']) or 
#             (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_CNT_UNINITIALIZED_DATA']) or
#             (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_TYPE_DSECT'])):

#         if ((section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_CNT_CODE']) and \
#             (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_READ']) and \
#             (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE'])) or \
#            (not ((section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_WRITE']) or 
#                  (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE']) or 
#                  (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_CNT_INITIALIZED_DATA']) or 
#                  (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_CNT_UNINITIALIZED_DATA']) or
#                  (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_TYPE_DSECT']))) and \
#            (not (section.Name.rstrip(b'\x00').lower().endswith(b'data') or section.Name.rstrip(b'\x00').lower() == b'.rsrc')):
        
        if (not executable_sections) or \
           (((section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_CNT_CODE']) and \
             (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_READ']) and \
             (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE'])) or \
            (not ((section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_WRITE'])) or 
                  (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE']) or 
                  (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_CNT_INITIALIZED_DATA']) or 
                  (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_CNT_UNINITIALIZED_DATA']) or
                  (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_TYPE_DSECT'])) and \
            (not (section.Name.rstrip(b'\x00').lower().endswith(b'data') or section.Name.rstrip(b'\x00').lower() == b'.rsrc' or section.Name.rstrip(b'\x00').lower() == b'.reloc'))):
            # 실행할 코드

            text_section = section
            if text_section is None or text_section.SizeOfRawData == 0:
                #print("Failed to find .text section")
                continue

            new_text = b''

            section_start = text_section.PointerToRawData
            section_end = section_start + text_section.SizeOfRawData

            old_nextPointer = section.PointerToRawData

            section_data = pe_data[section_start:section_end]
            virtual_address = text_section.VirtualAddress
            image_base = pe.OPTIONAL_HEADER.ImageBase

            bitness = 64 if pe.FILE_HEADER.Machine == 0x8664 else 32

            if bitness == 64:
                bit = KS_MODE_64

            elif bitness ==32:
                bit = KS_MODE_32

            decoder = Decoder(bitness, section_data, ip = image_base+virtual_address)

            formatter = Formatter(FormatterSyntax.NASM)

            for instr in decoder:
                asm_code = str(instr)
                instruction = pe_data[text_section.PointerToRawData + (instr.ip-(image_base+virtual_address)):text_section.PointerToRawData + (instr.next_ip-(image_base+virtual_address))]
                inst_dict [instr.ip] = asm_code 
            
    return inst_dict

def find_instruction_context(instructions, target_ip):
    sorted_ips = sorted(instructions.keys())  # 주소값 정렬
    index = sorted_ips.index(target_ip)  # 대상 IP의 인덱스 찾기
    # 다음 명령어 확인
    next_instructions = []
    
    for i in range(1, 4):  # 최대 3개까지 확인
        if index + i < len(sorted_ips):
            next_ip = sorted_ips[index + i]
            next_instructions.append(instructions[next_ip])
        else:
            break

        return next_instructions

@lru_cache(maxsize=None)
def to_little_endian(hex_str):
    # 2자리씩 끊어서 리스트로 만듭니다.
    bytes_list = [hex_str[i:i+2] for i in range(0, len(hex_str), 2)]
    # 리스트를 역순으로 뒤집습니다.
    bytes_list.reverse()
    # 다시 문자열로 결합합니다.
    little_endian_str = ''.join(bytes_list)
    return little_endian_str


def modify_headers(file_path, new_text):
    pe = pefile.PE(file_path)
    file_format = '.'+file_path.split('.')[-1]

    text_section = None
    new_text_list = []
    
    executable_sections = [
    hex(section.Characteristics) for section in pe.sections
    if section.Characteristics in [0x20000020, 0x60000020, 0x68000020,  0xA0000020, 0xE0000020] ]
    
    for section in pe.sections:
#         if (not (section.Name.rstrip(b'\x00').lower().endswith(b'data') or section.Name.rstrip(b'\x00').lower() == b'.rsrc')) and \
#            ((section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_CNT_CODE']) or \
#             (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_READ']) or \
#             (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE'])) and \
#            ((section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_WRITE']) or 
#             (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE']) or 
#             (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_CNT_INITIALIZED_DATA']) or 
#             (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_CNT_UNINITIALIZED_DATA']) or
#             (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_TYPE_DSECT'])):
            
#         if ((section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_CNT_CODE']) and \
#             (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_READ']) and \
#             (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE'])) or \
#            (not ((section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_WRITE']) or 
#                  (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE']) or 
#                  (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_CNT_INITIALIZED_DATA']) or 
#                  (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_CNT_UNINITIALIZED_DATA']) or
#                  (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_TYPE_DSECT']))) and \
#            (not (section.Name.rstrip(b'\x00').lower().endswith(b'data') or section.Name.rstrip(b'\x00').lower() == b'.rsrc')):
            
        if (not executable_sections) or \
           (((section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_CNT_CODE']) and \
             (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_READ']) and \
             (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE'])) or \
            (not ((section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_WRITE'])) or 
                  (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE']) or 
                  (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_CNT_INITIALIZED_DATA']) or 
                  (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_CNT_UNINITIALIZED_DATA']) or
                  (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_TYPE_DSECT'])) and \
            (not (section.Name.rstrip(b'\x00').lower().endswith(b'data') or section.Name.rstrip(b'\x00').lower() == b'.rsrc'))):
            # 실행할 코드
            
            dict_key = str(section.SizeOfRawData) + '_' + section.Name.rstrip(b'\x00').decode('utf-8', errors='ignore')
            
            
            text_section = section
            if dict_key not in new_text.keys():
                #print("Error: executable section not found")
                continue

            text_section.Misc = len(new_text[dict_key])
            new_size = int((len(new_text[dict_key]) + pe.OPTIONAL_HEADER.FileAlignment - 1) / pe.OPTIONAL_HEADER.FileAlignment) * pe.OPTIONAL_HEADER.FileAlignment
            new_text_data = new_text[dict_key] + b'\x00' * (new_size - len(new_text[dict_key]))
            new_text_list.append(new_text_data)
            
            size_diff = new_size - text_section.SizeOfRawData

            #print(f"[+] new Size of Raw Data: {hex(new_size)}")
            #print(f"[+] size diff: {hex(size_diff)}")

            text_section.SizeOfRawData = new_size
            pe.OPTIONAL_HEADER.SizeOfImage = max(pe.OPTIONAL_HEADER.SizeOfImage, text_section.VirtualAddress + new_size)

            prev_section = text_section
            for section in pe.sections:
                if section.VirtualAddress > text_section.VirtualAddress:
                    section.VirtualAddress = (prev_section.VirtualAddress + 
                                              (prev_section.Misc + pe.OPTIONAL_HEADER.SectionAlignment - 1) // pe.OPTIONAL_HEADER.SectionAlignment * pe.OPTIONAL_HEADER.SectionAlignment)
                    section.PointerToRawData += size_diff
                    prev_section = section
                    
            #section_idx +=1        
    pe.write(filename=file_path.replace(file_format, "_tmp"+file_format))
    pe.close()
    return new_text_list

def disassemble_and_modify(filepath, output_filepath):
    global old_rawPointer
    global old_nextPointer
    # PE 파일 열기
    #xor_list = []
    modified_text_section_dict={}
    
    reg_32 = ["eax", "ebx", "ecx", "edx", "edi", "esi"]
    reg_64 = ["rax", "rbx", "rcx", "rdx", "rdi", "rsi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
        
    mov_64 = ['push op1|pop op0|nop','nop|push op1|pop op0','push op1|nop|pop op0']
    
    mov_32 = ['push op1|pop op0'] # mov reg reg
    mov_32_0 = ['pushfd|xor op0,op0|popfd|nop','pushfd|sub op0,op0|popfd','pushfd|and op0,0|popfd'] # mov reg 0
    mov_32_1= ['pushfd| xor op0,op0|inc op0|popfd'] # mov reg 1
    #mov_32_hex = ['push op1|pop op0|nop|nop','nop|nop|push op1|pop op0','nop|push op1|nop|pop op0','push op1|nop|pop op0|nop','nop|push op1|pop op0|nop','push op1|nop|nop|pop op0'] # mov reg hex
    mov_32_hex = ['push op1|pop op0|nop|nop', 'nop|push op1|pop op0|nop', 'nop|nop|push op1|pop op0', 'push op1|nop|nop|pop op0', 'nop|push op1|nop|pop op0', 'push op1|nop|pop op0|nop', 'push op1|nop|nop|pop op0', 'nop|push op1|nop|pop op0']
    
    print("start : ",filepath)
    
    pe = pefile.PE(filepath)
    pe_data = open(filepath, "rb").read()

    # .text 섹션 데이터 가져오기
    text_section = None
    image_base = pe.OPTIONAL_HEADER.ImageBase
    
    inst_dict = inst_dict_generator(filepath)

    executable_sections = [
    hex(section.Characteristics) for section in pe.sections
    if section.Characteristics in [0x20000020, 0x60000020, 0x68000020,  0xA0000020, 0xE0000020] ]
    
    
    for section in pe.sections:
        #print(section)
#         if (not (section.Name.rstrip(b'\x00').lower().endswith(b'data') or section.Name.rstrip(b'\x00').lower() == b'.rsrc' or section.Name.rstrip(b'\x00').lower() == b'.reloc')) and \
#            ((section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_CNT_CODE']) or \
#             (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_READ']) or \
#             (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE'])) and \
#            ((section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_WRITE']) or 
#             (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE']) or 
#             (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_CNT_INITIALIZED_DATA']) or 
#             (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_CNT_UNINITIALIZED_DATA']) or
#             (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_TYPE_DSECT'])):

#         if ((section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_CNT_CODE']) and \
#             (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_READ']) and \
#             (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE'])) or \
#            (not ((section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_WRITE']) or 
#                  (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE']) or 
#                  (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_CNT_INITIALIZED_DATA']) or 
#                  (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_CNT_UNINITIALIZED_DATA']) or
#                  (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_TYPE_DSECT']))) and \
#            (not (section.Name.rstrip(b'\x00').lower().endswith(b'data') or section.Name.rstrip(b'\x00').lower() == b'.rsrc')):
        
                    
        if (not executable_sections)  or \
           (((section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_CNT_CODE']) and \
             (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_READ']) and \
             (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE'])) or \
            (not ((section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_WRITE'])) or 
                  (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE']) or 
                  (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_CNT_INITIALIZED_DATA']) or 
                  (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_CNT_UNINITIALIZED_DATA']) or
                  (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_TYPE_DSECT'])) and \
            (not (section.Name.rstrip(b'\x00').lower().endswith(b'data') or section.Name.rstrip(b'\x00').lower() == b'.rsrc' or section.Name.rstrip(b'\x00').lower() == b'.reloc'))):
            # 실행할 코드

            text_section = section
            
            if text_section is None or text_section.SizeOfRawData == 0:
                print("Failed to find .text section")
                continue
            
            new_text = b''
            
            # .text 섹션의 데이터 가져오기
            old_rawPointer = text_section.PointerToRawData
            old_size = text_section.Misc

            section_start = text_section.PointerToRawData
            section_end = section_start + text_section.SizeOfRawData
            
            old_nextPointer = section.PointerToRawData

            section_data = pe_data[section_start:section_end]
            virtual_address = text_section.VirtualAddress
            image_base = pe.OPTIONAL_HEADER.ImageBase


            bitness = 64 if pe.FILE_HEADER.Machine == 0x8664 else 32

            if bitness ==64:
                bit = KS_MODE_64

            elif bitness ==32:
                bit = KS_MODE_32

            decoder = Decoder(bitness, section_data, ip = image_base+virtual_address)

            formatter = Formatter(FormatterSyntax.NASM)

            for instr in decoder:
                try:

                    disasm = formatter.format(instr)
                    op = disasm.split(' ')[0]

                    asm_code = str(instr)
                    operands = asm_code.split(' ')[-1]
                    op_0 = operands.split(',')[0]
                    op_1 = operands.split(',')[-1]

                    instruction = pe_data[text_section.PointerToRawData + (instr.ip-(image_base+virtual_address)):text_section.PointerToRawData + (instr.next_ip-(image_base+virtual_address))]
  
                    if bitness == 64 and ((op_0 not in reg_64)):
                        new_text+=  instruction
                        continue
    

                    if bitness == 32 and ((op_0 not in reg_32 and op_1 not in reg_32) or len(op_0) == 2 or len(op_1) == 2) and not op_0.isdigit():
                        new_text+=  instruction
                        continue

                    if bool(re.search(r"[\[\]]", operands)) or 'rbp' in operands or 'rsp' in operands or 'esp' in operands or 'ebp' in operands:     
                        new_text+=  instruction
                        continue

                    if 'int3' == op:
                        machine_code = assemble_asm('nop', KS_ARCH_X86, bit)
                        mc_code =  bytes.fromhex("".join("{:02x}".format(byte) for byte in machine_code))
                        new_text+=  mc_code
                        continue
                        
                    if 'nop' == op:
                        machine_code = assemble_asm('int3', KS_ARCH_X86, bit)
                        mc_code =  bytes.fromhex("".join("{:02x}".format(byte) for byte in machine_code))
                        new_text+=  mc_code
                        continue

                    if 'add' == op:
                        if ((op_0 in reg_32 and op_1 in reg_32) or (op_0 in reg_64 and op_1 in reg_64)):
                            if op_0 == op_1:
                                new_ins = 'shl '+op_0+', 1'
                                machine_code = assemble_asm(new_ins, KS_ARCH_X86, bit)
                                mc_code =  bytes.fromhex("".join("{:02x}".format(byte) for byte in machine_code))
                                #print(asm_code, len(instruction), len(mc_code))
                                if (len(mc_code) == len(instruction)):
                                    new_text += mc_code
                                    continue

                                else:
                                    new_text += instruction
                                    continue
                                
                            else:
                                new_text += instruction
                                continue

                        new_ins = 'sub '+op_0+', -'+op_1

                        machine_code = assemble_asm(new_ins, KS_ARCH_X86, bit)
                        mc_code =  bytes.fromhex("".join("{:02x}".format(byte) for byte in machine_code))
                    
                        after_insts = find_instruction_context(inst_dict, instr.ip)
                        op_0_insts = [instr for instr in after_insts if op_0 in instr]

                        if (len(mc_code) == len(instruction) and '-' not in str(mc_code)):          
                            if op_0_insts and all(op_0 in instr for instr in op_0_insts):
                                new_text += instruction
                                continue
                                
                            else:
                                new_text += mc_code
                                continue
                            
                        else:
                            new_text += instruction
                            continue

                    if 'sub' == op:
                       # print(asm_code)
                        if ((op_0 in reg_32 and op_1 in reg_32) or (op_0 in reg_64 and op_1 in reg_64)):
                            if op_0 == op_1:
                                new_ins = 'xor '+op_0+', '+op_1
                                machine_code = assemble_asm(new_ins, KS_ARCH_X86, bit)
                                mc_code =  bytes.fromhex("".join("{:02x}".format(byte) for byte in machine_code))
                                if (len(mc_code) == len(instruction)):
                                    new_text += mc_code
                                    continue
                                
                            else:
                                new_text += instruction
                                continue


                        new_ins = 'add '+op_0+', -'+op_1

                        machine_code = assemble_asm(new_ins, KS_ARCH_X86, bit)
                        mc_code =  bytes.fromhex("".join("{:02x}".format(byte) for byte in machine_code))
                        

                        after_insts = find_instruction_context(inst_dict, instr.ip)
                        op_0_insts = [instr for instr in after_insts if op_0 in instr]
                        
                        if (len(mc_code) == len(instruction) and '-' not in str(mc_code)):  
                            
                            if op_0_insts and all(op_0 in instr for instr in op_0_insts) or (len(op_1)==9):
                                new_text += instruction
                                continue

                            else:
                                new_text += mc_code
                                continue

                        else:
                            new_text += instruction
                            continue


                    elif 'xor' == op:

                        if op_0 in reg_64 and op_1 in reg_64:
                            new_text+=  instruction
                            continue
                            
                        if op_0 == op_1:

                            new_ins = 'sub '+op_0+','+op_1
                            machine_code = assemble_asm(new_ins, KS_ARCH_X86, bit)
                            mc_code =  bytes.fromhex("".join("{:02x}".format(byte) for byte in machine_code))    

                            if len(machine_code)<len(instruction):
                                n_machine_code = machine_code
                                for i in range(0,len(instruction)-len(machine_code)):
                                    n_machine_code.append(0)

                                mc_code =  bytes.fromhex("".join("{:02x}".format(byte) for byte in machine_code))  
                            new_text+=  mc_code
                            continue
                            
                        else:
                            new_text+=  instruction
                            continue
                        
                    elif 'test' == op and op_0 == op_1:   
                        new_ins = 'or '+op_0+','+op_1

                        machine_code = assemble_asm(new_ins, KS_ARCH_X86, bit)
                        mc_code =  bytes.fromhex("".join("{:02x}".format(byte) for byte in machine_code))
                        new_text += mc_code
                        continue
                        
                    
                    elif 'or' == op and op_0 == op_1:   
                        new_ins = 'test '+op_0+','+op_1

                        machine_code = assemble_asm(new_ins, KS_ARCH_X86, bit)
                        mc_code =  bytes.fromhex("".join("{:02x}".format(byte) for byte in machine_code))
                        new_text += mc_code
                        continue


                    elif 'mov' == op:
                        if op_0 == op_1:
                            new_ins = 'nop;nop'
                            machine_code = assemble_asm(new_ins, KS_ARCH_X86, bit)
                            mc_code =  bytes.fromhex("".join("{:02x}".format(byte) for byte in machine_code))     
                            new_text += mc_code
                            continue


                        if bitness ==32:
                            
                            if (len(op_0) == 2) or (len(op_1) == 2):
                                new_text += bytes.fromhex((section_data[instr.ip:instr.ip+instr.len]))
                                continue 

                            if bool(re.search(r"\s*,\s*0*\s*$", operands)):
                                change_instr = random.choice(mov_32_0)
                                change_instr = change_instr.replace('op1',op_1)
                                change_instr = change_instr.replace('op0',op_0)
                                change_instr = change_instr.replace('|',';')
                                machine_code = assemble_asm(change_instr, KS_ARCH_X86, bit)
                                mc_code =  bytes.fromhex("".join("{:02x}".format(byte) for byte in machine_code))
                                
                                if len(mc_code) < len(instruction):
                                    while len(mc_code) < len(instruction):
                                        mc_code+=b'\x90'
                                                                
                                new_text += mc_code
                                continue


                            elif bool(re.search(r"\s*,\s*1*\s*$", operands)):
                                change_instr = random.choice(mov_32_1)
                                change_instr = change_instr.replace('op1',op_1)
                                change_instr = change_instr.replace('op0',op_0)
                                change_instr = change_instr.replace('|',';')
                                machine_code = assemble_asm(change_instr, KS_ARCH_X86, bit)
                                mc_code =  bytes.fromhex("".join("{:02x}".format(byte) for byte in machine_code))
                                
                                if len(mc_code) < len(instruction):
                                    while len(mc_code) < len(instruction):
                                        mc_code+=b'\x90'
                                    
                                new_text += mc_code
                                continue

                            elif bool(re.search(r"(?P<a>e..),(?P<b>0?x?([0-7][0-9A-Fa-f]|[0-9A-Fa-f]))$", operands)):
                                change_instr = random.choice(mov_32_hex)
                                change_instr = change_instr.replace('op1',op_1)
                                change_instr = change_instr.replace('op0',op_0)
                                change_instr = change_instr.replace('|',';')
                                machine_code = assemble_asm(change_instr, KS_ARCH_X86, bit)
                                mc_code =  bytes.fromhex("".join("{:02x}".format(byte) for byte in machine_code))

                                if len(mc_code) < len(instruction):
                                    while len(mc_code) < len(instruction):
                                        mc_code+=b'\x90'
                                    
                                new_text += mc_code
                                continue

                            else:  
                                if (len(op_0) == 2) or (len(op_1) == 2):
                                    new_text += instruction
                                    continue  

                                change_instr = random.choice(mov_32)
                                change_instr = change_instr.replace('op1',op_1)
                                change_instr = change_instr.replace('op0',op_0)
                                change_instr = change_instr.replace('|',';')                               

                                try:
                                    machine_code = assemble_asm(change_instr, KS_ARCH_X86, bit)
                                    mc_code =  bytes.fromhex("".join("{:02x}".format(byte) for byte in machine_code))

                                except KsError:
                                    mc_code = instruction

                                if len(mc_code) == len(instruction):                   
                                    new_text += mc_code
                                    continue

                                if len(mc_code) < len(instruction):
                                    while len(mc_code) < len(instruction):
                                        mc_code+=b'\x90'

                                    new_text += mc_code
                                    continue

                                else:
                                    new_text +=  instruction
                                    continue
                                    
                except KsError:
                    new_text +=  instruction
                    continue
                        
                else:
                    new_text +=  instruction
                    continue

            #print("modified_section : ",len(new_text), "| original section : ", len(section_data), "|", section.SizeOfRawData)
            
            modified_text_section_dict[str(section.SizeOfRawData) + '_' + text_section.Name.rstrip(b'\x00').decode('utf-8', errors='ignore')] = new_text
    return modified_text_section_dict
    
def modify_section(file_path, new_text, save_dir, modified_section_names):
    global old_rawPointer
    global old_nextPointer
    
    modified_section_names = list(modified_section_names)  
    file_format = '.'+file_path.split('.')[-1]    
    pe = pefile.PE(file_path)

    with open(file_path, "rb") as tmp:
        tmp_binary = tmp.read()
        #print("ending pe size : ",len(tmp_binary))

    tmp_file = file_path.replace(file_format, "_tmp"+file_format)
    
    with open(tmp_file, "rb") as tmp:
        tmp_binary = tmp.read()
        #print(len(tmp_binary))
        
    section_idx = 0
    header_checker = 0
    
    #section_cnt = len(modified_section_names)
    new_binary = b''    
    
    for idx, section in enumerate(pe.sections):
        last_modified = 0
        non_match = 0
        for section_name in modified_section_names:
            if section_name.lower() == str(section.SizeOfRawData) + '_' + section.Name.rstrip(b'\x00').decode('utf-8', errors='ignore').lower():  
                text_section = section
                #print("match : ", section_name, section.Name.strip(b'\x00').lower(), section_idx)
                
                if section_idx == 0:
                    #print("  header")
                    old_rawPointer = text_section.PointerToRawData
                    new_binary = tmp_binary[:old_rawPointer]
                    new_binary += new_text[section_idx]
                    section_idx += 1
                    
                else:
                    #print("  body")
                    new_binary += new_text[section_idx]
                    section_idx += 1
                
                modified_section_names.remove(section_name)
                
                if not modified_section_names:
                    last_modified = 1
                break

            else:
                non_match = 1

        if non_match ==1 or ():
            #print("non match middel section 1111: ",section.Name.strip(b'\x00').lower())
            new_binary += tmp_binary[section.PointerToRawData:section.PointerToRawData + section.SizeOfRawData]
            continue
            
        if not modified_section_names and last_modified != 1:
            #print("non match end section 2222: ",section.Name.strip(b'\x00').lower())
            
            if (header_checker == 0 and section_idx == 0):
                old_rawPointer = section.PointerToRawData
                new_binary = tmp_binary[:old_rawPointer]
                #new_binary += new_text[section_idx]s
                header_checker+=1
            
            new_binary += tmp_binary[section.PointerToRawData:section.PointerToRawData + section.SizeOfRawData]
            #print("    -->",len(new_binary))
            continue
            
    
    if idx == len(pe.sections) - 1: #overlay
        new_binary += tmp_binary[section.PointerToRawData+section.SizeOfRawData:] 
            
    with open(file_path.replace(file_format, "_changing"+file_format), "wb") as f:
        f.write(new_binary)
    #print("last : ",len(new_binary))    
    os.remove(tmp_file)
    #print("save : ",save_dir)
    file_name = file_path.split('/')[-1].replace(file_format, "_changing"+file_format)
    print("Done!! : ",file_path.replace(file_format, "_changing"+file_format), "| ",save_dir+file_name,"\n")
    #shutil.move(save_dir+file_name,file_path) 
    os.rename(file_path.replace(file_format, "_changing"+file_format), save_dir+file_name)
    #print(file_path.replace(file_format, "_changing"+file_format))
    os.system('rm -rf '+file_path.replace(file_format, "_changing"+file_format))
    
def process_sample(args):
    sample, root, save_dir = args
    input_filepath = os.path.join(root, sample)
    output_filename = sample.replace('.exe', '_changing.exe')
    output_filepath = os.path.join(save_dir, output_filename)

    #이미 파일이 존재하는 경우 건너뜀
#     if os.path.isfile(output_filepath):
#         return

    try:
        new_text = disassemble_and_modify(input_filepath, save_dir)
        if new_text is None:
            print(f"[+] Error: Failed to create new_text section for {sample}.")
            
        else:
            modified_section_names = new_text.keys()
            new_text = modify_headers(input_filepath, new_text)
            modify_section(input_filepath, new_text, save_dir + '/', modified_section_names)
            
    except pefile.PEFormatError:
        pass
    
def list_files_by_size(directory):
    # Return a list of files in the directory sorted by size
    files_with_sizes = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            if os.path.isfile(file_path):
                files_with_sizes.append((file, os.path.getsize(file_path), root))
    # Sort files by size (smallest to largest)
    files_with_sizes.sort(key=lambda x: x[1])
    return [file[0] for file in files_with_sizes]  # Return only file names

def create_directory(dir_path):
    if not os.path.exists(dir_path):
        os.makedirs(dir_path)

def main():
#     sample_dir = '../sample/Dike_benign/'
#     save_dir_base = '../sample/benign_AE/instruction_change/'
    
#     sample_dir = '../sample/Dike_malware/'
#     save_dir_base = '../sample/perturbated_labling_sample/instruction_change/'
    
    sample_dir = '../sample/perturbated_labling_sample/increase_section/'
    save_dir_base = '../sample/perturbated_labling_sample/increase_section+instruction_change/'
    
#     sample_dir = '../sample/perturbated_labling_sample/resource_change/'
#     save_dir_base = '../sample/perturbated_labling_sample/instruction_change+resource_change/'
    
#     sample_dir = '../sample/perturbated_labling_sample/resource_change_1002/'
#     save_dir_base = '../sample/perturbated_labling_sample/rsrc_change+instruction_change_1002/'
    
    #sample_dir = '../sample/perturbated_labling_sample/adding_nop/'
    #save_dir_base = '../sample/perturbated_labling_sample/adding_nop+instruction_change/'
    
#     sample_dir = '../Share_malware/Seed_malware'
#     save_dir_base = '../Share_malware/AE/instruction_change/'
    
#     sample_dir = '../Share_malware/AE/resource_change'
#     save_dir_base = '../Share_malware/AE/instruction_change+resource_change/'

#     sample_dir = '../sample/benign'
#     save_dir_base = '../sample/sample_AE/'

#     sample_dir = '../sample/sample_AE/increase_section/'
#     save_dir_base = '../sample/sample_AE/increase_section+instruction_change/'

    tasks = []

    for root, dirs, files in os.walk(sample_dir):
        # 'ok' 디렉토리가 있는 경우 건너뛰기
        if 'ok' in root.split(os.sep):
            continue

        # 저장할 디렉토리 생성
        save_dir = os.path.join(save_dir_base, os.path.basename(root))
        create_directory(save_dir)

#         # 파일을 파일 크기 순으로 정렬
        #samples = list_files_by_size(root)

        for sample in files:
            #if 'iexplore_32.exe' not in sample:
            #if 'hello_world.exe' not in sample:
            #if 'putty.exe' not in sample:
            #if '3240bf7ea2f814bf8a3fec63f291232ff772f40185c7b749bab9ecc0afeba119' not in sample:
                #continue
            if any(ext in sample for ext in ['.ipynb', '.pickle', '.txt', '.zip','_tmp']):# or '.' not in sample:
                continue

            tasks.append((sample, root, save_dir))

    num_processes = max(1, multiprocessing.cpu_count() // 2)

    # 멀티프로세싱 Pool을 사용하여 작업 병렬 실행
    with multiprocessing.Pool(processes=num_processes) as pool:
        pool.map(process_sample, tasks)

    print("All tasks are completed.")

if __name__ == '__main__':
    main()