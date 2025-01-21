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
from add_section import *
import lief
import gc

old_rawPointer = 0
old_nextPointer = 0

def itob4hex(data: int) -> bytes:
    return data.to_bytes(4, byteorder="little", signed=True).hex()

def inst_dict_generator(filepath):
    pe = pefile.PE(filepath)
    pe_data = open(filepath, "rb").read()

    # .text 섹션 데이터 가져오기
    text_section = None

    inst_dict={}
        
    executable_sections = [
    hex(section.Characteristics) for section in pe.sections
    if section.Characteristics in [0x20000020, 0x60000020, 0x68000020,  0xA0000020, 0xE0000020] ]
    need_bytes = 0

    for section in pe.sections:
        
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
            print(section.Name.rstrip(b'\x00').lower())
            #print(new_section)

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
                
                operands = asm_code.split(' ')[-1]
                op_0 = operands.split(',')[0]
                op_1 = operands.split(',')[-1]
                
                instruction = pe_data[text_section.PointerToRawData + (instr.ip-(image_base+virtual_address)):text_section.PointerToRawData + (instr.next_ip-(image_base+virtual_address))]
                #inst_dict [instr.ip] = asm_code
                
                if 'call' in asm_code and 'h' in asm_code and '[' not in asm_code and ']' not in asm_code and ':' not in asm_code:
                
                    s_strat = image_base+virtual_address
                    s_end = s_strat + text_section.Misc_VirtualSize

                    match = re.search(r"\[([0-9A-Fa-f]+)h\]", operands)  # 대괄호 안의 주소 값 찾기
                    
                    if match:
                        addr_hex = int(match.group(1), 16)  # 16진수 변환
                    else:
                        addr_hex = int(operands[:-1], 16)  # "h" 제거 후 변환

                    if s_strat <= addr_hex < s_end:
                        inst_dict [instr.ip] = (instr, instruction)
                        need_bytes+=12
            
    return inst_dict, need_bytes

def section_adding(filepath, need_byte):
    data = bytearray(open(filepath, "rb").read())
    
    new_section_data = b"\x00"*need_byte
    
    new_data = add_section(data, ".new", new_section_data, PERM.READ | PERM.WRITE | PERM.EXEC)
    output_filename = filepath.replace('.exe', '_new_section.exe')
    print(output_filename)
    open(output_filename, "wb").write(new_data)
    
    return output_filename
    
def disassemble_and_modify(filepath, output_filepath):
    global old_rawPointer
    global old_nextPointer
    
    print("Start Processing:", filepath)
    
    inst_dict, need_byte = inst_dict_generator(filepath)
    new_filepath = section_adding(filepath, need_byte)
    
    print("New Filepath:", new_filepath)
    
    pe = pefile.PE(new_filepath)
    pe_data = bytearray(open(new_filepath, "rb").read())  # Convert to bytearray for modification
    ori_pe_data = pe_data
    
    # ✅ `lief`를 사용하여 PE 파일 저장
    lief_binary = lief.parse(new_filepath)

    image_base = pe.OPTIONAL_HEADER.ImageBase

    # Find the newly added section (.new)
    new_section = next((section for section in pe.sections if section.Name.rstrip(b'\x00').lower() == b'.new'), None)
    if not new_section:
        print("Error: .new section not found!")
        return

    new_section_virtual_address = new_section.VirtualAddress
    new_section_start = image_base + new_section_virtual_address  # 논리 주소
    byte_array_new_section_start = new_section.PointerToRawData  # 파일 오프셋
    
    executable_sections = [
        hex(section.Characteristics) for section in pe.sections
        if section.Characteristics in [0x20000020, 0x60000020, 0x68000020,  0xA0000020, 0xE0000020]
    ]
    
    for section in pe.sections:
        if section.Name.rstrip(b'\x00').lower() == b'.new':
            section.content = list(pe_data[section.PointerToRawData:section.PointerToRawData + section.SizeOfRawData])
            continue
            
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
            
            pe_section_name = None  # 초기화
            text_section = section
            pe_section_name = section.Name.strip(b'\x00').decode(errors="ignore").lower()
    
            print("Text Section Found:", pe_section_name)

            section_start = text_section.PointerToRawData
            section_end = section_start + text_section.SizeOfRawData
            virtual_address = text_section.VirtualAddress

            bitness = 64 if pe.FILE_HEADER.Machine == 0x8664 else 32
            bit = KS_MODE_64 if bitness == 64 else KS_MODE_32

            # Loop through instructions and modify
            for address, instruction in inst_dict.items():
                asm_code, machine_code = instruction
                next_addr = address + len(machine_code)

                # 🛠 `.new` 섹션의 다음 오프셋 계산
                new_section_next = new_section_start + len(machine_code) + len(assemble_asm("inc eax; dec eax;", KS_ARCH_X86, bit)) + 5  # `JMP` 추가 고려
                byte_array_new_section_next = byte_array_new_section_start + (new_section_next - new_section_start)  # 파일 오프셋 계산

                # 🛠 `.text` 섹션에서 JMP 명령어 삽입
                jmp_offset = itob4hex(new_section_start - address - 5)
                new_instruction = "e9" + jmp_offset

                text_start_idx = text_section.PointerToRawData + (address - (image_base + virtual_address))
                text_end_idx = text_section.PointerToRawData + (next_addr - (image_base + virtual_address))
                pe_data[text_start_idx:text_end_idx] = bytes.fromhex(new_instruction)

                return_offset = itob4hex(next_addr - new_section_next)
                ori_call_addr = int(str(asm_code).split(' ')[-1].replace('h', ''), 16)
                call_offset = itob4hex(ori_call_addr - (new_section_start + 5))  # 📌 +5 고려

                machine_code = "e8" + call_offset
                # 🛠 `NOP` 및 복귀 `JMP` 명령어 생성
                new_ins = "inc eax; dec eax;"
                semantic_nop = assemble_asm(new_ins, KS_ARCH_X86, bit)
                mc_code = bytes.fromhex("".join("{:02x}".format(byte) for byte in semantic_nop))

                return_instruction = "e9" + return_offset

                # 🛠 `.new` 섹션에 추가할 명령어 생성
                new_section_inst = bytes.fromhex(machine_code)  # Convert to bytearray
                new_section_inst += bytearray(mc_code)  # Append semantic NOP
                new_section_inst += bytes.fromhex(return_instruction)  # Append return JMP

                # 🛠 `.new` 섹션의 크기가 부족하면 확장
                if byte_array_new_section_next > len(pe_data):
                    pe_data.extend(b'\x00' * (byte_array_new_section_next - len(pe_data)))

                # 🛠 `.new` 섹션에 명령어 쓰기
                pe_data[byte_array_new_section_start:byte_array_new_section_next] = new_section_inst

                # ✅ **오프셋 갱신 (수정된 부분)**
                new_section_start = new_section_next  # Move logical address
                byte_array_new_section_start = byte_array_new_section_next  # Move file offset
                
            # ✅ **Update PE Header Information**
            pe.OPTIONAL_HEADER.SizeOfImage = max(pe.OPTIONAL_HEADER.SizeOfImage, new_section.VirtualAddress + new_section.Misc_VirtualSize)
            pe.OPTIONAL_HEADER.SizeOfHeaders = pe.sections[0].PointerToRawData
            pe.FILE_HEADER.NumberOfSections = len(pe.sections)

            # ✅ **Save Modified PE File**
            modified_filepath = filepath.replace(".exe", "_modified.exe")
            

            # 🔹 `.text`와 `.new` 섹션을 `lief`에서 업데이트 후 저장
            for section in lief_binary.sections:
                #print(section.name, type(section.name))
                #print("?? : ",section.name.rstrip("\x00").lower(), pe_section_name.lower())
                if section.name.lower() == pe_section_name.lower():
                    section.content = list(pe_data[section.pointerto_raw_data:section.pointerto_raw_data+section.sizeof_raw_data])
                elif section.name.lower() == ".new":
                    section.content = list(pe_data[new_section.PointerToRawData:new_section.PointerToRawData + new_section.SizeOfRawData])
               

    lief_binary.write(output_filepath)
    
    # ✅ **임시 파일 삭제**
    if os.path.exists(new_filepath):
        os.remove(new_filepath)  # `os.remove()`를 사용하여 파일 삭제
        print(f"🗑 Deleted temporary file: {new_filepath}")
    else:
        print(f"⚠ Warning: {new_filepath} not found.")

    print(f"✅ PE File Successfully Modified: {output_filepath}")
    
def process_sample(args):
    sample, root, save_dir = args
    input_filepath = os.path.join(root, sample)
    output_filename = sample.replace('.exe', '_changing.exe')
    output_filepath = os.path.join(save_dir, output_filename)

    #이미 파일이 존재하는 경우 건너뜀
#     if os.path.isfile(output_filepath):
#         return

    disassemble_and_modify(input_filepath, output_filepath)

    
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
    
    sample_dir = '../sample/Dike_malware/'
    save_dir_base = '../sample/perturbated_labling_sample/call_modifier/'
    
#     sample_dir = '../sample/perturbated_labling_sample/increase_section/'
#     save_dir_base = '../sample/perturbated_labling_sample/increase_section+instruction_change/'
    
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
            #if 'calc.exe' not in sample:
            #if 'hello_world.exe' not in sample:
            #if 'putty.exe' not in sample:
            #if 'b51a7da0a9bb7ef1b02ecd0f450f6f724e5ff84f054c9538128a0c3cd4af4973' not in sample:
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