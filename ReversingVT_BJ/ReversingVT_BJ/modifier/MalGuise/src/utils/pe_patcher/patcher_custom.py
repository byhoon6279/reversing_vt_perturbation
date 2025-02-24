import sys
import os
from pathlib import Path
p = Path(os.path.abspath(__file__))
base_path = str(p.parents[3])
sys.path.append(base_path)
#sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../')))
import lief
import os
import pefile
import mmap
import os.path as osp
import random
from src.utils.pe_patcher.assemble import assembler
from src.utils.semnops import get_semantic_nop
import argparse
from pathlib import Path
import json



def align(val_to_align, alignment):
    return int(((val_to_align + alignment - 1) // alignment) * alignment)

def addSection(path=None, bytez = None, data_hash=None, size_increase_budget=0x1000, step_num=None):
    if bytez:
        binary = lief.parse(list(bytez))
    else:
        binary = lief.parse(path)

    if step_num is None:
        section_name = ".htext"
    else:
        section_name = ".htext" + str(step_num)
    alignment = binary.optional_header.section_alignment
    imagebase = binary.optional_header.imagebase
    section_size =  align(size_increase_budget, alignment)
    # section_size = config.Problem_Attack.size_of_new_section
    section_text                 = lief.PE.Section(section_name)
    section_text.content         = [144]*section_size
    section_text.size            = section_size
    # section_text.virtual_address = addr_of_new_section
    section_text.characteristics = (lief.PE.SECTION_CHARACTERISTICS.MEM_READ
                            | lief.PE.SECTION_CHARACTERISTICS.MEM_WRITE
                            | lief.PE.SECTION_CHARACTERISTICS.CNT_INITIALIZED_DATA
                            | lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE)
    
    #lief.PE.SECTION_CHARACTERISTICS.CNT_CODE | lief.PE.SECTION_CHARACTERISTICS.MEM_READ | lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE

    binary.add_section(section_text, lief.PE.SECTION_TYPES.TEXT)
    builder = lief.PE.Builder(binary)
    builder.build()
    return bytes(builder.get_build())

def get_arch_w_pefile(pe):
    machine_type = pe.FILE_HEADER.Machine
    if machine_type == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386']:
        return 'x86'
    elif machine_type == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']:
        return 'amd64'
    elif machine_type == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_ARM'] or machine_type == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_ARMNT']:
        return 'arm'
    raise Exception("Unknown or not supported architecture")

def get_arch(binary):
    machine_type = int(binary.header.machine)
    if machine_type == 0x014c: # pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386']:
        return 'x86'
    elif machine_type == 0x8664: #pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']:
        return 'amd64'
    elif machine_type == 0x01c0 or 0x01c4: #'IMAGE_FILE_MACHINE_ARM' or 'IMAGE_FILE_MACHINE_ARMNT'
        return 'arm'
    raise Exception("Unknown or not supported architecture")

def get_byte_data(arch, asm, addr):
    assembler_obj = assembler(arch)
    data = assembler_obj.asm(asm, addr=addr)
    
    data = bytes(data)
    byte_data_str = [hex(i) for i in bytearray(data)]
    byte_data = list(map(eval, byte_data_str))
    return data

def get_semnops(arch, injected_length, imagebase, 
                semnop_list, max_random_number, 
                rva_to_be_injected, addr_to_be_called, 
                next_addr, budget, context_free_semnops):
    size_exceed = False
    i = 0
    while True:
        i += 1
        if i > 5:
            size_exceed = True
            modify_list = {}
            return size_exceed, 0, modify_list, ""
        if context_free_semnops:
            nop_bytes, uidxs = get_semantic_nop(max_random_number, get_unconstrained_idxs=True)
            shellcodenops = bytes([ord(b) for b in nop_bytes])
            # print(hex(rva_to_be_injected), hex(addr_to_be_called), hex(next_addr))
            shellcodecall = get_byte_data(
                                arch=arch, 
                                asm="call " + str(addr_to_be_called), 
                                addr = imagebase + rva_to_be_injected
                            )
            
            shellcodejmp = get_byte_data(
                                arch=arch, 
                                asm="jmp " + str(next_addr), 
                                addr = imagebase + rva_to_be_injected + len(shellcodenops) + 5
                            )
            
            shellcode = shellcodecall + shellcodenops + shellcodejmp
            modify_list = {'context_free_semnops': max_random_number}
        else:
            asm_list=[]
            modify_list = {}
            for _semnop in semnop_list:
                modify_list[_semnop] = random.randint(0, max_random_number)
                semnop = _semnop * modify_list[_semnop]
                asm_list.append(semnop)
            
            asm = ""
            # random.shuffle(asm_list)
            for code in asm_list:
                asm+=code
            shellcode = get_byte_data(
                            arch=arch, 
                            asm="call "+ str(addr_to_be_called) + "\n" + asm + "jmp " + str(next_addr), 
                            addr = imagebase + rva_to_be_injected
                        )
            
        length_of_injected_code = len(shellcode)
        if length_of_injected_code + injected_length < budget:
            return size_exceed, length_of_injected_code, modify_list, shellcode

def patch_in_slack_space(bytez, max_random_number, size_increase_budget, imagebase, 
                         rva_to_be_injected, injected_length, target_call_addr, 
                         step_num=None, semnop_list=[]):
    pe_to_be_patched = pefile.PE(data = bytez)
    arch = get_arch_w_pefile(pe_to_be_patched)
    call_addr, next_addr, addr_to_be_called, have_logic, have_cmp = target_call_addr
    call_addr, next_addr, addr_to_be_called = eval(call_addr), eval(next_addr), eval(addr_to_be_called)
    size_exceed, length_of_injected_code, modify_list, shellcode = \
                            get_semnops(
                                arch, injected_length, imagebase, 
                                semnop_list, max_random_number, 
                                rva_to_be_injected, addr_to_be_called, 
                                next_addr, size_increase_budget
                            )
    if size_exceed:
        return bytez, rva_to_be_injected, injected_length, modify_list, size_exceed
    
    first_section = pe_to_be_patched.get_section_by_rva(rva_to_be_injected)
    
    offset = first_section.get_PointerToRawData_adj()

    pe_to_be_patched.__data__[offset + first_section.Misc_VirtualSize: offset + first_section.Misc_VirtualSize + len(shellcode)] = shellcode

    shellcode = get_byte_data(
                    arch=arch, 
                    asm="jmp "+str(imagebase + rva_to_be_injected), 
                    addr = call_addr
                )
    pe_to_be_patched.set_bytes_at_rva(call_addr - imagebase, shellcode)

    patched_bytez = bytes(pe_to_be_patched.__data__)
    next_rva_to_be_injected = rva_to_be_injected + length_of_injected_code
    return patched_bytez, next_rva_to_be_injected, length_of_injected_code + injected_length, modify_list, size_exceed

def patch_in_new_section(bytez, max_random_number, size_increase_budget, imagebase, 
                         rva_to_be_injected, injected_length, target_call_addr, 
                         step_num=None, semnop_list=[]):
    
    pe_to_be_patched = pefile.PE(data = bytez)
    section_alignment = pe_to_be_patched.OPTIONAL_HEADER.SectionAlignment
    new_section_size =  align(size_increase_budget, section_alignment)
    call_addr, next_addr, addr_to_be_called, have_logic, have_cmp = target_call_addr
    call_addr, next_addr, addr_to_be_called = eval(call_addr), eval(next_addr), eval(addr_to_be_called)
    arch = get_arch_w_pefile(pe_to_be_patched)

    size_exceed, length_of_injected_code, modify_list, shellcode = \
                            get_semnops(
                                arch, injected_length, imagebase, 
                                semnop_list, max_random_number, 
                                rva_to_be_injected, addr_to_be_called, 
                                next_addr, new_section_size
                            )
    if size_exceed:
        return bytez, rva_to_be_injected, injected_length, modify_list, size_exceed
    
    pe_to_be_patched.set_bytes_at_rva(rva_to_be_injected, shellcode)

    shellcode = get_byte_data(
                    arch=arch, 
                    asm="jmp " + str(imagebase + rva_to_be_injected), 
                    addr = call_addr
                )
    pe_to_be_patched.set_bytes_at_rva(call_addr - imagebase, shellcode)
    patched_bytez = bytes(pe_to_be_patched.__data__)
    next_rva_to_be_injected = rva_to_be_injected + length_of_injected_code
    return patched_bytez, next_rva_to_be_injected, length_of_injected_code + injected_length, modify_list, size_exceed

def patch(
        attack_params, 
        bytez, 
        size_increase_budget, 
        imagebase, 
        rva_to_be_injected, 
        injected_length, 
        target_call_addr, 
        step_num=None, 
        semnop_list=[]
        ):
    pe_to_be_patched = pefile.PE(data = bytez)
    max_random_number = attack_params.max_random_number
    attack_strategy = attack_params.attack_strategy
    context_free_semnops = attack_params.context_free_semnops
    if attack_strategy == 'new_section':
        section_alignment = pe_to_be_patched.OPTIONAL_HEADER.SectionAlignment
        budget =  align(size_increase_budget, section_alignment)
    elif attack_strategy == 'slack_space':
        budget = size_increase_budget
    else:
        raise Exception("Unknown attack strategy")
    call_addr, next_addr, addr_to_be_called, have_logic, have_cmp = target_call_addr
    call_addr, next_addr, addr_to_be_called = eval(call_addr), eval(next_addr), eval(addr_to_be_called)
    arch = get_arch_w_pefile(pe_to_be_patched)

    size_exceed, length_of_injected_code, modify_list, shellcode = \
                            get_semnops(
                                arch, injected_length, imagebase, 
                                semnop_list, max_random_number, 
                                rva_to_be_injected, addr_to_be_called, 
                                next_addr, budget, context_free_semnops
                            )
    # print(shellcode)
    if size_exceed:
        return bytez, rva_to_be_injected, injected_length, modify_list, size_exceed
    
    if attack_strategy == 'new_section':
        pe_to_be_patched.set_bytes_at_rva(rva_to_be_injected, shellcode)
    elif attack_strategy == 'slack_space':
        pe_to_be_patched.__data__ = bytearray(pe_to_be_patched.__data__)
        first_section = pe_to_be_patched.get_section_by_rva(rva_to_be_injected)
        offset1 = first_section.get_PointerToRawData_adj()
        offset2 = rva_to_be_injected - first_section.VirtualAddress
        pe_to_be_patched.__data__[offset1 + offset2 : offset1 + offset2 + len(shellcode)] = shellcode
    else:
        raise Exception("Unknown attack strategy")

    shellcode = get_byte_data(
                    arch=arch, 
                    asm="jmp " + str(imagebase + rva_to_be_injected), 
                    addr = call_addr
                )
    pe_to_be_patched.set_bytes_at_rva(call_addr - imagebase, shellcode)
    patched_bytez = bytes(pe_to_be_patched.__data__)
    next_rva_to_be_injected = rva_to_be_injected + length_of_injected_code
    return patched_bytez, next_rva_to_be_injected, length_of_injected_code + injected_length, modify_list, size_exceed

def GetSlack(filename):
    pe = pefile.PE(filename)
    # Find the first executable section
    first_section = None
    # last_section = pe.sections[-1]
    for i in range(len(pe.sections)):
        section = pe.sections[i]
        if section.Characteristics & pefile.SECTION_CHARACTERISTICS["IMAGE_SCN_MEM_EXECUTE"]:
            first_section = section
            break

    if first_section is None:
        print("No executable section found in {}.".format(filename))
        return 0, 0

    if i == len(pe.sections) - 1:
        print("No section found after the first executable section in {}.".format(filename))
        return 0, 0
    else:
        next_section = pe.sections[i + 1]

    # Calculate the slack space
    slack_space = next_section.VirtualAddress - (first_section.VirtualAddress + first_section.Misc_VirtualSize)
    first_section.SizeOfRawData = next_section.VirtualAddress - first_section.VirtualAddress
    offset = first_section.get_PointerToRawData_adj()
    pe.__data__[offset + first_section.Misc_VirtualSize : offset + first_section.SizeOfRawData] = b'\x00' * slack_space
    
    return bytes(pe.__data__), slack_space, first_section.VirtualAddress + first_section.Misc_VirtualSize

def patch_yourself(filename, call_infos, output_path):
    bytez, slack_space, rva_to_be_injected = GetSlack(filename)
    pe = pefile.PE(data = bytez)
    arch = get_arch_w_pefile(pe)
    pe.__data__ = bytearray(pe.__data__)
    first_section = pe.get_section_by_rva(rva_to_be_injected)
    imagebase = pe.OPTIONAL_HEADER.ImageBase
    offset = first_section.get_PointerToRawData_adj()
    pe.__data__[offset + first_section.Misc_VirtualSize : offset + first_section.SizeOfRawData] = b'\x00' * slack_space

    context_free_semnops = True
    
    for idx, call_info in enumerate(call_infos):
        #print(idx)
        if context_free_semnops:
            byte_length = 60
            nop_bytes, uidxs = get_semantic_nop(byte_length, get_unconstrained_idxs=True)
            shellcodecall = get_byte_data(
                                arch=arch, 
                                asm="call " + call_info[2], 
                                addr = imagebase + rva_to_be_injected
                            )

            shellcodejmp = get_byte_data(
                                arch=arch, 
                                asm="jmp " + call_info[1], 
                                addr = imagebase + rva_to_be_injected + byte_length + 5
                            )

            shellcodesemnop = shellcodecall + bytes([ord(b) for b in nop_bytes]) + shellcodejmp
        else:
            asm = 'nop\n'*20
            rva_to_be_injected = first_section.VirtualAddress + first_section.Misc_VirtualSize
            shellcodesemnop = get_byte_data(
                            arch=get_arch_w_pefile(pe), 
                            asm="call "+ call_info[2] + "\n" + asm + "jmp " + call_info[1], 
                            addr = imagebase + rva_to_be_injected
                        )

        pe.__data__[offset + first_section.Misc_VirtualSize: offset + first_section.Misc_VirtualSize + len(shellcodesemnop)] = shellcodesemnop

        shellcode = get_byte_data(arch=get_arch_w_pefile(pe), asm="jmp "+str(imagebase + rva_to_be_injected), addr = eval(call_info[0]))
        pe.set_bytes_at_rva(eval(call_info[0]) - imagebase, shellcode)
    pe.write(output_path)

def get_data(json_file)->dict:
    try:
        f = open(json_file, 'r')
        line = f.readline()  
        data = json.loads(line.strip())
        f.close()
    except:
        data = {}
    return data

    
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', default = '', type = str, dest = 'filename')
    args = parser.parse_args()
    file_path = args.filename
    base_dir = Path(file_path).resolve().parent
    file_name = file_path.split('/')[-1]

    call_addr_file = str(base_dir)+'/'+file_name + '.txt'
    call_addr_list = get_data(call_addr_file)
    output_path = str(base_dir)+'/'+file_name.replace('.exe','_semantic_nop.exe')
    patch_yourself(file_path, call_addr_list, output_path)