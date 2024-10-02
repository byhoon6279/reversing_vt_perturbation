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

    for section in pe.sections:
        if (not (section.Name.rstrip(b'\x00').lower().endswith(b'data') or section.Name.rstrip(b'\x00').lower() == b'.rsrc' or section.Name.rstrip(b'\x00').lower() == b'.reloc')) and \
           ((section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_CNT_CODE']) or \
            (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_READ']) or \
            (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE'])) and \
           ((section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_WRITE']) or 
            (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE']) or 
            (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_CNT_INITIALIZED_DATA']) or 
            (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_CNT_UNINITIALIZED_DATA']) or
            (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_TYPE_DSECT'])):

            text_section = section
            if text_section is None or text_section.SizeOfRawData == 0:
                print("Failed to find .text section")
                continue
            #print("Section : ",section.Name.rstrip(b'\x00'))
            # 변경된 .text 섹션 데이터를 저장할 변수
            new_text = b''

            section_start = text_section.PointerToRawData
            section_end = section_start + text_section.SizeOfRawData

            old_nextPointer = section.PointerToRawData

            section_data = pe_data[section_start:section_end]
            virtual_address = text_section.VirtualAddress
            image_base = pe.OPTIONAL_HEADER.ImageBase

            bitness = 64 if pe.FILE_HEADER.Machine == 0x8664 else 32

            print("bit : ",bitness)

            if bitness ==64:
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

    # Find the .text section
    text_section = None
    #section_idx = 0
    new_text_list = []
    
    for section in pe.sections:
        if (not (section.Name.rstrip(b'\x00').lower().endswith(b'data') or section.Name.rstrip(b'\x00').lower() == b'.rsrc')) and \
           ((section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_CNT_CODE']) or \
            (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_READ']) or \
            (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE'])) and \
           ((section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_WRITE']) or 
            (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE']) or 
            (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_CNT_INITIALIZED_DATA']) or 
            (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_CNT_UNINITIALIZED_DATA']) or
            (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_TYPE_DSECT'])):
            
            dict_key = section.Name.rstrip(b'\x00')
            
            text_section = section
            
            if dict_key not in new_text.keys():
                print("Error: .text section not found")
                continue

            text_section.Misc = len(new_text[dict_key])
            new_size = int((len(new_text[dict_key]) + pe.OPTIONAL_HEADER.FileAlignment - 1) / pe.OPTIONAL_HEADER.FileAlignment) * pe.OPTIONAL_HEADER.FileAlignment
            new_text_data = new_text[dict_key] + b'\x00' * (new_size - len(new_text[dict_key]))
            new_text_list.append(new_text_data)
            
            size_diff = new_size - text_section.SizeOfRawData

            print(f"[+] new Size of Raw Data: {hex(new_size)}")
            print(f"[+] size diff: {hex(size_diff)}")

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
    xor_list = []
    modified_text_section_dict={}
    
    reg_32 = ["eax", "ebx", "ecx", "edx", "edi", "esi"]
    reg_64 = ["rax", "rbx", "rcx", "rdx", "rdi", "rsi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
        
    mov_64 = ['push op1|pop op0|nop','nop|push op1|pop op0','push op1|nop|pop op0']
    
    mov_32 = ['push op1|pop op0'] # mov reg reg
    mov_32_0 = ['pushfd|xor op0,op0|popfd|nop','pushfd|sub op0,op0|popfd|nop','pushfd|and op0,0|popfd'] # mov reg 0
    mov_32_1= ['pushfd| xor op0,op0|inc op0|popfd'] # mov reg 1
    mov_32_hex = ['push op1|pop op0|nop|nop','nop|nop|push op1|pop op0','nop|push op1|nop|pop op0','push op1|nop|pop op0|nop','nop|push op1|pop op0|nop','push op1|nop|nop|pop op0'] # mov reg hex
    print("89 : ",filepath)
    pe = pefile.PE(filepath)
    pe_data = open(filepath, "rb").read()

    # .text 섹션 데이터 가져오기
    text_section = None
    image_base = pe.OPTIONAL_HEADER.ImageBase
    
    inst_dict = inst_dict_generator(filepath)
    
    for section in pe.sections:
        if (not (section.Name.rstrip(b'\x00').lower().endswith(b'data') or section.Name.rstrip(b'\x00').lower() == b'.rsrc' or section.Name.rstrip(b'\x00').lower() == b'.reloc')) and \
           ((section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_CNT_CODE']) or \
            (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_READ']) or \
            (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE'])) and \
           ((section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_WRITE']) or 
            (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE']) or 
            (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_CNT_INITIALIZED_DATA']) or 
            (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_CNT_UNINITIALIZED_DATA']) or
            (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_TYPE_DSECT'])):

            text_section = section
            if text_section is None or text_section.SizeOfRawData == 0:
                print("Failed to find .text section")
                continue
            
            print("Target : ",section.Name.rstrip(b'\x00').lower())
            # 변경된 .text 섹션 데이터를 저장할 변수
            new_text = b''
            
            # .text 섹션의 데이터 가져오기
            old_rawPointer = text_section.PointerToRawData
            old_size = text_section.Misc

            section_start = text_section.PointerToRawData
            section_end = section_start + text_section.SizeOfRawData
            
            #section_start = text_section.VirtualAddress + image_base
            #section_end = section_start + text_section.Misc_VirtualSize

            old_nextPointer = section.PointerToRawData

            section_data = pe_data[section_start:section_end]
            virtual_address = text_section.VirtualAddress
            image_base = pe.OPTIONAL_HEADER.ImageBase


            bitness = 64 if pe.FILE_HEADER.Machine == 0x8664 else 32
            print("bit : ",bitness)

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

                    if bitness == 32 and ((op_0 not in reg_32 and op_1 not in reg_32) or len(op_0) == 2 or len(op_1) == 2):
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
                            
                            new_ins = 'sbb '+op_0+', '+op_1
                            machine_code = assemble_asm(new_ins, KS_ARCH_X86, bit)
                            mc_code =  bytes.fromhex("".join("{:02x}".format(byte) for byte in machine_code))
                            #print(asm_code, len(instruction), len(mc_code))
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
                            if op_0_insts and all(op_0 in instr for instr in op_0_insts):
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

                    elif 'test' == op and op_0 == op_1:   
                        new_ins = 'or '+op_0+','+op_1

                        machine_code = assemble_asm(new_ins, KS_ARCH_X86, bit)
                        mc_code =  bytes.fromhex("".join("{:02x}".format(byte) for byte in machine_code))
                        new_text += mc_code
                        continue

                    elif 'mov' == op:
                        if op_0 == op_1:
                            xor_list.append(instr)
                            new_ins = 'nop;nop'
                            machine_code = assemble_asm(new_ins, KS_ARCH_X86, bit)
                            mc_code =  bytes.fromhex("".join("{:02x}".format(byte) for byte in machine_code))
                            new_text += mc_code
                            continue

    #                     if bitness ==64:

    #                         if (op_0 in reg_64[6:] and op_1 in reg_64[6:]):
    #                             new_text += instruction
    #                             continue  

    #                         if bool(re.search(r"\s*,\s*\d*\s*$", operands)):
    #                             op_0 = operands.split(',')[0]
    #                             op_1 = operands.split(',')[-1]

    #                             change_instr = random.choice(mov_64)
    #                             change_instr = change_instr.replace('op1',op_1)
    #                             change_instr = change_instr.replace('op0',op_0)
    #                             change_instr = change_instr.replace('|',';')
    #                             machine_code = assemble_asm(change_instr, KS_ARCH_X86, bit)

    #                             if len(machine_code)<len(section_data[instr.ip:instr.ip+instr.len]):
    #                                 for i in range(0,len(section_data[instr.ip:instr.ip+instr.len])-len(machine_code)):
    #                                     change_instr+=';nop'

    #                             machine_code = assemble_asm(change_instr, KS_ARCH_X86, bit)
    #                             mc_code =  bytes.fromhex("".join("{:02x}".format(byte) for byte in machine_code))
    #                             new_text += mc_code
    #                             continue

    #                         else:
    #                             change_instr = random.choice(mov_64)
    #                             change_instr = change_instr.replace('op1',op_1)
    #                             change_instr = change_instr.replace('op0',op_0)
    #                             change_instr = change_instr.replace('|',';')

    #                             if op_0 in reg_64[6:] or op_1 in reg_64[6:]:
    #                                 change_instr = change_instr.replace('nop','')

    #                             if bool(re.search(r"[h]", operands)):
    #                                 new_text += instruction
    #                                 continue  

    #                             try:
    #                                 machine_code = assemble_asm(change_instr, KS_ARCH_X86, bit)
    #                                 mc_code =  bytes.fromhex("".join("{:02x}".format(byte) for byte in machine_code))
    #                                 new_text += mc_code
    #                                 continue

    #                             except KsError:
    #                                 mc_code = instruction
    #                                 new_text += mc_code
    #                                 continue

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
                                new_text += mc_code
                                continue


                            elif bool(re.search(r"\s*,\s*1*\s*$", operands)):
                                change_instr = random.choice(mov_32_1)
                                change_instr = change_instr.replace('op1',op_1)
                                change_instr = change_instr.replace('op0',op_0)
                                change_instr = change_instr.replace('|',';')
                                machine_code = assemble_asm(change_instr, KS_ARCH_X86, bit)
                                mc_code =  bytes.fromhex("".join("{:02x}".format(byte) for byte in machine_code))
                                new_text += mc_code
                                continue

                            elif bool(re.search(r"(?P<a>e..),(?P<b>0?x?([0-7][0-9A-Fa-f]|[0-9A-Fa-f]))$", operands)):
                                change_instr = random.choice(mov_32_hex)
                                change_instr = change_instr.replace('op1',op_1)
                                change_instr = change_instr.replace('op0',op_0)
                                change_instr = change_instr.replace('|',';')
                                machine_code = assemble_asm(change_instr, KS_ARCH_X86, bit)
                                mc_code =  bytes.fromhex("".join("{:02x}".format(byte) for byte in machine_code))
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

            print("modified_section : ",len(new_text), "| original section : ", len(section_data), "|", section.SizeOfRawData)
            
            modified_text_section_dict[text_section.Name.rstrip(b'\x00')] = new_text
    return modified_text_section_dict
    
def modify_section(file_path, new_text, save_dir, modified_section_names):
    global old_rawPointer
    global old_nextPointer
    
    modified_section_names = list(modified_section_names)
    
    file_format = '.'+file_path.split('.')[-1]
    
    pe = pefile.PE(file_path)
    
    tmp_file = file_path.replace(file_format, "_tmp"+file_format)
    with open(tmp_file, "rb") as tmp:
        tmp_binary = tmp.read()
        
    section_idx = 0
    section_cnt = len(modified_section_names)
    new_binary = b''
    #print("modified_section_names : ",modified_section_names)
    for section in pe.sections:
        for section_cnt, section_name in enumerate(modified_section_names):
            if section_name.lower() == section.Name.strip(b'\x00').lower():    
                text_section = section
                if section_cnt == 0:
                    old_rawPointer = text_section.PointerToRawData
                    new_binary = tmp_binary[:old_rawPointer]
                    new_binary += new_text[section_idx]
                    new_binary += tmp_binary[text_section.PointerToRawData+text_section.SizeOfRawData:]

                else:
                    new_binary += new_text[section_idx]
                    new_binary += tmp_binary[text_section.PointerToRawData+text_section.SizeOfRawData:]
                
                section_idx += 1
                section_cnt -= 1
                #print(section_idx, section_cnt)
                if section_cnt == 0 or section_cnt == -1:
                    break
                    
            else:
                if not new_binary:
                    old_rawPointer = section.PointerToRawData
                    new_binary = tmp_binary[:old_rawPointer]
                    new_binary = new_text
                    
            new_binary += tmp_binary[section.PointerToRawData+section.SizeOfRawData:]
    
    print("fp : ",file_path, len(new_binary))
    
    with open(file_path.replace(file_format, "_changing"+file_format), "wb") as f:
        f.write(new_binary)
        
    os.remove(tmp_file)
    print("save : ",save_dir)
    file_name = file_path.split('/')[-1].replace(file_format, "_changing"+file_format)
    print("Done!! : ",file_path.replace(file_format, "_changing"+file_format), "| ",save_dir+file_name,"\n")
    #shutil.move(save_dir+file_name,file_path) 
    os.rename(file_path.replace(file_format, "_changing"+file_format), save_dir+file_name)
    #print(file_path.replace(file_format, "_changing"+file_format))
    os.system('rm -rf '+file_path.replace(file_format, "_changing"+file_format))
    
#-------------------------------------------singel_processing------------------------------------   
# if __name__ == "__main__":
    
#     #sample_dir = '../sample/input_sample/'
#     #save_dir = '../sample/perturbated_sample/instruction_change/'
    
#     sample_dir = '../sample/benign/'
#     #sample_dir = '../../../../DikeDataset/files/malware/'
#     save_dir = '../'
    
# #     sample_dir = '../sample/labeling/'
# #     save_dir_base = '../sample/perturbated_labling_sample/instruction_change/'
                 
#     samples = list_files_by_size(sample_dir)
#     create_directory(save_dir)

#     for sample in samples:
                 
#         if 'PEview.exe' not in sample:
#              continue
                 
#         if '.ipynb' in sample or '.pickle' in sample or '.txt' in sample or '.zip' in sample or '.' not in sample:
#             continue
        
#         print(sample)

#         input_filepath = sample_dir+sample
        
#         new_text = disassemble_and_modify(input_filepath, save_dir)
#         print("len : ",len(new_text))
        
#         if new_text is None:
#             print(f"[+] Error : failed to make new_text section.")
#         else:
#             modified_section_names = new_text.keys()
#             new_text = modify_headers(input_filepath, new_text)
#             modify_section(input_filepath, new_text, save_dir,modified_section_names)

#-------------------------------------------malware_family_multi_processing------------------------------------       
# def process_sample(args):
#     sample, root, save_dir = args
#     file_path = os.path.join(root, sample)
#     output_filename_1 = sample.replace('.exe', '_changing.exe')
#     output_filepath_1 = os.path.join(save_dir, output_filename_1)

#     if os.path.isfile(output_filepath_1):
#         return

#     try:
#         new_text = disassemble_and_modify(file_path, save_dir)

#         if new_text is None:
#             print(f"[+] Error: Failed to create new_text section for {sample}.")
#         else:
#             new_text = modify_headers(file_path, new_text)
#             modify_section(file_path, new_text, save_dir+'/')
            
#     except pefile.PEFormatError:
#         pass

# def main():
#     #sample_dir = '../sample/labeling/'
#     #save_dir_base = '../sample/perturbated_labling_sample/instruction_change/'
    
    
#     sample_dir = '../sample/perturbated_labling_sample/adding_nop'
#     save_dir_base = '../sample/perturbated_labling_sample/adding_nop+instruction_change/'
    
#     tasks = []

#     for root, dirs, files in os.walk(sample_dir):
#         if 'ok' in root.split(os.sep):
#             continue

#         if len(files) <= 10:
#             continue
        
#         save_dir = os.path.join(save_dir_base, os.path.basename(root))
#         create_directory(save_dir + '/')
        
#         for sample in list_files_by_size(root):
#             if any(ext in sample for ext in ['.ipynb', '.pickle', '.txt', '.zip']) or '.' not in sample:
#                 continue

#             tasks.append((sample, root, save_dir))

#     num_processes = max(1, multiprocessing.cpu_count() // 2)

#     with multiprocessing.Pool(processes=num_processes) as pool:
#         pool.map(process_sample, tasks)

#     print("All tasks are completed.")

# if __name__ == '__main__':
#     main()
# #---------------------------------------------------------------------------------------------- label single processing
# if __name__ == "__main__":
    
#     sample_dir = '../sample/perturbated_labling_sample/adding_nop/'
#     save_dir = '../sample/perturbated_labling_sample/adding_nop+instruction_change/'
    
    
#     for root, dirs, files in os.walk(sample_dir):
#         # 'OK' 디렉토리가 있는 경우 건너뛰기
#         if 'ok' in root.split(os.sep):
#             continue
            
# #         if len(files)<=10:
# #             continue
            
#         print(save_dir+root.split('/')[-1])
        
#         samples = list_files_by_size(root)
#         create_directory(save_dir+root.split('/')[-1])
                
#         for sample in samples:
#             if '.ipynb' in sample or '.pickle' in sample or '.txt' in sample or '.zip' in sample or '.' not in sample:
#                 continue
                
# #             if '1c766fa73e8e9e642109da0a68d981f7e4219776fb6ed5f2a2a5b4c618237138.exe' not in sample:
# #                 continue
                
#             if os.path.isfile(save_dir+root.split('/')[-1]+'/'+sample.replace('.exe','_changing.exe')):
#                 continue

#             print(root, sample)

#             input_filepath = root+'/'+sample
            
#             try:
#                 new_text = disassemble_and_modify(input_filepath, save_dir+root.split('/')[-1])
#                 print(len(new_text), type(new_text))
                
                
#                 modified_section_names = new_text.keys()
                
#                 print(modified_section_names)
                
#                 for i,j in enumerate(modified_section_names):
#                     print(i,j)
#                 print('----------------------------------------------------')
                
#                 if new_text is None:
#                     print(f"[+] Error : failed to make new_text section.")
#                 else:
#                     new_text = modify_headers(input_filepath, new_text)
#                     print(type(new_text), len(new_text), len(new_text[0]))
#                     modify_section(input_filepath, new_text, save_dir+root.split('/')[-1]+'/', modified_section_names)
#             except pefile.PEFormatError:
#                 continue
                
#--------------------------------------------------------------------------- multiprocessing_label - 이거로 쓰세용
def process_sample(args):
    sample, root, save_dir = args
    input_filepath = os.path.join(root, sample)
    output_filename = sample.replace('.exe', '_changing.exe')
    output_filepath = os.path.join(save_dir, output_filename)

    # 이미 파일이 존재하는 경우 건너뜀
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
#     sample_dir = '../sample/labeling/'
#     save_dir_base = '../sample/perturbated_labling_sample/instruction_change_new_9/'
    
    sample_dir = '../sample/perturbated_labling_sample/resource_change_1002/'
    save_dir_base = '../sample/perturbated_labling_sample/rsrc_change+instruction_change_1002/'
    
    #sample_dir = '../sample/perturbated_labling_sample/adding_nop/'
    #save_dir_base = '../sample/perturbated_labling_sample/adding_nop+instruction_change/'

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
#             if 'bbdf913509673e6abdae0630c5abb5d0ca2eb14ab0fae0a48af3cdf20c5c4f93' not in sample:
#                 continue
            if any(ext in sample for ext in ['.ipynb', '.pickle', '.txt', '.zip']) or '.' not in sample:
                continue

            tasks.append((sample, root, save_dir))

    num_processes = max(1, multiprocessing.cpu_count() // 2)

    # 멀티프로세싱 Pool을 사용하여 작업 병렬 실행
    with multiprocessing.Pool(processes=num_processes) as pool:
        pool.map(process_sample, tasks)

    print("All tasks are completed.")

if __name__ == '__main__':
    main()

#--------------------------------------------------------------------------- multiprocessing_label
# def process_sample(args):
#     sample, root, save_dir = args
#     input_filepath = os.path.join(root, sample)
#     output_filename = sample.replace('.exe', '_changing.exe')
#     output_filepath = os.path.join(save_dir, output_filename)

#     # 이미 파일이 존재하는 경우 건너뜀
#     if os.path.isfile(output_filepath):
#         return

#     try:
#         new_text = disassemble_and_modify(input_filepath, save_dir)
#         if new_text is None:
#             print(f"[+] Error: Failed to create new_text section for {sample}.")
#         else:
#             #print("len_new_text : ",len(new_text), new_text)
#             modified_section_names = new_text.keys()
#             new_text = modify_headers(input_filepath, new_text)
#             modify_section(input_filepath, new_text, save_dir + '/', modified_section_names)
            
#     except pefile.PEFormatError:
#         pass
    
# def list_files_by_size(directory):
#     # Return a list of files in the directory sorted by size
#     files_with_sizes = []
#     for root, dirs, files in os.walk(directory):
#         for file in files:
#             file_path = os.path.join(root, file)
#             if os.path.isfile(file_path):
#                 files_with_sizes.append((file, os.path.getsize(file_path), root))
#     # Sort files by size (smallest to largest)
#     files_with_sizes.sort(key=lambda x: x[1])
#     return [file[0] for file in files_with_sizes]  # Return only file names

# def create_directory(dir_path):
#     if not os.path.exists(dir_path):
#         os.makedirs(dir_path)

# def main():
#     sample_dir = '../sample/labeling/'
#     save_dir_base = '../sample/perturbated_labling_sample/instruction_change/'

#     tasks = []

#     for root, dirs, files in os.walk(sample_dir):
#         # 'ok' 디렉토리가 있는 경우 건너뛰기
#         if 'ok' in root.split(os.sep):
#             continue

#         # 저장할 디렉토리 생성
#         save_dir = os.path.join(save_dir_base, os.path.basename(root))
#         create_directory(save_dir)

#         # 파일을 파일 크기 순으로 정렬
#         for sample in files:
#             if any(ext in sample for ext in ['.ipynb', '.pickle', '.txt', '.zip']) or '.' not in sample:
#                 continue

#             tasks.append((sample, root, save_dir))

#     # 싱글 프로세싱으로 순차적으로 작업 처리
#     for task in tasks:
#         process_sample(task)

#     print("All tasks are completed.")

# if __name__ == '__main__':
#     main()
