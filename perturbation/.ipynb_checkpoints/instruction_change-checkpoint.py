import pefile
from iced_x86 import *
from pe_library import *
from iced_x86 import *
from typing import Union, Dict, Sequence 
from types import ModuleType
import binascii
from keystone import *
import pandas as pd
import shutil
from common_function import *
import multiprocessing

old_rawPointer = 0
old_nextPointer = 0

def modify_headers(file_path, new_text, fin = None):
    pe = pefile.PE(file_path)
    file_format = '.'+file_path.split('.')[-1]

    # Find the .text section
    text_section = None
    section_idx = 0
    new_text_list = []
    
    for section in pe.sections:
        #if b'.text' in section.Name.strip(b'\x00').lower():
        if (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_CNT_CODE']) and (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_READ']) and \
           ((section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_WRITE']) or 
            (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE']) or \
           (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_CNT_INITIALIZED_DATA'])):
            
            text_section = section
            
            if text_section is None:
                print("Error: .text section not found")
                return

            text_section.Misc = len(new_text[section_idx])
            new_size = int((len(new_text[section_idx]) + pe.OPTIONAL_HEADER.FileAlignment - 1) / pe.OPTIONAL_HEADER.FileAlignment) * pe.OPTIONAL_HEADER.FileAlignment
            new_text_data = new_text[section_idx] + b'\x00' * (new_size - len(new_text[section_idx]))
            new_text_list.append(new_text_data)
            
            size_diff = new_size - text_section.SizeOfRawData

            if fin:
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
                    
            section_idx +=1
            
    pe.write(filename=file_path.replace(file_format, "_tmp"+file_format))
    pe.close()
    return new_text_list

def disassemble_and_modify(filepath, output_filepath):
    global old_rawPointer
    global old_nextPointer
    # PE 파일 열기
    xor_list = []
    modified_text_section_list = []
    
    reg_32 = ["eax", "ebx", "ecx", "edx", "edi", "esi"]
    reg_64 = ["rax", "rbx", "rcx", "rdx", "rdi", "rsi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
        
    mov_64 = ['push op1|pop op0|nop','nop|push op1|pop op0','push op1|nop|pop op0']
    
    mov_32 = ['push op1|pop op0'] # mov reg reg
    mov_32_0 = ['pushfd|xor op0,op0|popfd|nop','pushfd|sub op0,op0|popfd|nop','pushfd|and op0,0|popfd'] # mov reg 0
    mov_32_1= ['pushfd| xor op0,op0|inc op0|popfd'] # mov reg 1
    mov_32_hex = ['push op1|pop op0|nop|nop','nop|nop|push op1|pop op0','nop|push op1|nop|pop op0','push op1|nop|pop op0|nop','nop|push op1|pop op0|nop','push op1|nop|nop|pop op0'] # mov reg hex

    pe = pefile.PE(filepath)
    pe_data = open(filepath, "rb").read()

    # .text 섹션 데이터 가져오기
    text_section = None
    
    for section in pe.sections:
        #if section.Name.decode().strip('\x00').lower() == ".text" or section.Name.decode().strip('\x00').upper() == "CODE":
        #if section.Name.decode().strip('\x00').lower() in ['.text', 'text', 'code', '.code']:
        if (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_CNT_CODE']) and (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_READ']) and \
           ((section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_WRITE']) or 
            (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE']) or \
           (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_CNT_INITIALIZED_DATA'])):
            text_section = section
    
            if text_section is None or text_section.SizeOfRawData == 0:
                print(
                    "Failed to find .text section")
                return
            
            # 변경된 .text 섹션 데이터를 저장할 변수
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
            print("bit : ",bitness)

            if bitness ==64:
                bit = KS_MODE_64

            elif bitness ==32:
                bit = KS_MODE_32

            decoder = Decoder(bitness, section_data, ip = image_base+virtual_address)

            formatter = Formatter(FormatterSyntax.NASM)

            for instr in decoder:

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

                    if bitness ==64:

                        if (op_0 in reg_64[6:] and op_1 in reg_64[6:]):
                            new_text += instruction
                            continue  

                        if bool(re.search(r"\s*,\s*\d*\s*$", operands)):
                            op_0 = operands.split(',')[0]
                            op_1 = operands.split(',')[-1]

                            change_instr = random.choice(mov_64)
                            change_instr = change_instr.replace('op1',op_1)
                            change_instr = change_instr.replace('op0',op_0)
                            change_instr = change_instr.replace('|',';')
                            machine_code = assemble_asm(change_instr, KS_ARCH_X86, bit)

                            if len(machine_code)<len(section_data[instr.ip:instr.ip+instr.len]):
                                for i in range(0,len(section_data[instr.ip:instr.ip+instr.len])-len(machine_code)):
                                    change_instr+=';nop'

                            machine_code = assemble_asm(change_instr, KS_ARCH_X86, bit)
                            mc_code =  bytes.fromhex("".join("{:02x}".format(byte) for byte in machine_code))
                            new_text += mc_code
                            continue

                        else:
                            change_instr = random.choice(mov_64)
                            change_instr = change_instr.replace('op1',op_1)
                            change_instr = change_instr.replace('op0',op_0)
                            change_instr = change_instr.replace('|',';')

                            if op_0 in reg_64[6:] or op_1 in reg_64[6:]:
                                change_instr = change_instr.replace('nop','')

                            if bool(re.search(r"[h]", operands)):
                                new_text += instruction
                                continue  

                            try:
                                machine_code = assemble_asm(change_instr, KS_ARCH_X86, bit)
                                mc_code =  bytes.fromhex("".join("{:02x}".format(byte) for byte in machine_code))
                                new_text += mc_code
                                continue

                            except KsError:
                                mc_code = instruction
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

                            else:
                                new_text +=  instruction
                                continue
                else:
                    new_text +=  instruction
                    continue

            print("modified_section : ",len(new_text), "| original section : ", len(section_data), "|", section.SizeOfRawData)
            
            modified_text_section_list.append(new_text)

    return modified_text_section_list
    
def modify_section(file_path, new_text, save_dir):
    global old_rawPointer
    global old_nextPointer
    
    #number_of_nop = str(number_of_nop)
    file_format = '.'+file_path.split('.')[-1]
    
    pe = pefile.PE(file_path)
    
    tmp_file = file_path.replace(file_format, "_tmp"+file_format)
    
    with open(tmp_file, "rb") as tmp:
        tmp_binary = tmp.read()
        
    section_idx = 0
    
    for section in pe.sections:
        #if b'.text' in section.Name.strip(b'\x00').lower():
        if (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_CNT_CODE']) and (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_READ']) and \
           ((section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_WRITE']) or 
            (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE']) or \
           (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_CNT_INITIALIZED_DATA'])):
            text_section = section
            #print(text_section)        
            if section_idx == 0:
                old_rawPointer = text_section.PointerToRawData
                new_binary = tmp_binary[:old_rawPointer]
            
            new_binary += new_text[section_idx]
            new_binary += tmp_binary[text_section.PointerToRawData+text_section.SizeOfRawData:]
            section_idx +=1

    with open(file_path.replace(file_format, "_changing"+file_format), "wb") as f:
        f.write(new_binary)
        
    os.remove(tmp_file)
    
    file_name = file_path.split('/')[-1].replace(file_format, "_changing"+file_format)
    print("Done!! : ",file_path.replace(file_format, "_changing"+file_format), "| ",save_dir+file_name,"\n")
    #shutil.move(save_dir+file_name,file_path) 
    os.rename(file_path.replace(file_format, "_changing"+file_format), save_dir+file_name)
    
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
#             new_text = modify_headers(input_filepath, new_text)
#             modify_section(input_filepath, new_text, save_dir)

#-------------------------------------------malware_family_multi_processing------------------------------------
def process_sample(sample, root, save_dir):
    input_filepath = os.path.join(root, sample)
    output_filename = sample.replace('.exe', '_changing.exe')
    output_filepath = os.path.join(save_dir, output_filename)
    
    if os.path.isfile(output_filepath):
        return  # 이미 처리된 파일은 건너뜀

    try:
        new_text = disassemble_and_modify(input_filepath, save_dir)

        if new_text is None:
            print(f"[+] Error: Failed to create new_text section for {sample}.")
        else:
            new_text = modify_headers(input_filepath, new_text)
            modify_section(input_filepath, new_text, save_dir+'/')
    except pefile.PEFormatError:
        pass

def worker(input_queue):
    while True:
        task = input_queue.get()
        if task is None:
            break
        sample, root, save_dir = task
        process_sample(sample, root, save_dir)
        input_queue.task_done()

def main():
    sample_dir = '../sample/labeling/'
    save_dir_base = '../sample/perturbated_labling_sample/instruction_change/'
    
    # 작업 큐 생성
    input_queue = multiprocessing.JoinableQueue()

    # CPU 코어 수의 절반만 사용하도록 설정
    num_processes = max(1, multiprocessing.cpu_count() // 5)

    # 워커 프로세스 생성 및 시작
    processes = []
    for _ in range(num_processes):
        p = multiprocessing.Process(target=worker, args=(input_queue,))
        p.start()
        processes.append(p)

    for root, dirs, files in os.walk(sample_dir):
        if 'ok' in root.lower().split(os.sep):  # 'OK' 디렉토리를 건너뛰기
            continue
            
        if len(files) <= 10:  # 파일이 10개 이하인 디렉토리는 건너뛰기
            continue
        
        save_dir = os.path.join(save_dir_base, os.path.basename(root))
        create_directory(save_dir)
        
        for sample in files:
            if any(ext in sample for ext in ['.ipynb', '.pickle', '.txt', '.zip']) or '.' not in sample:
                continue
            
            input_queue.put((sample, root, save_dir))

    # 모든 작업이 완료되면 None을 넣어 워커 프로세스를 종료시킴
    input_queue.join()
    for _ in range(num_processes):
        input_queue.put(None)

    # 워커 프로세스 종료
    for p in processes:
        p.join()

    print("All tasks are completed.")

if __name__ == '__main__':
    main()
