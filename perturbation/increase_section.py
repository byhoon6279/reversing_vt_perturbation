import lief
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

def increase_section_size_with_nop(file_path, output_file, increase_size, nop_count):
    """
    PE 파일의 각 섹션 크기를 사용자가 지정한 바이트만큼 증가시키고,
    섹션 끝에 NOP (0x90)를 지정한 개수만큼 추가하며,
    섹션 헤더와 관련된 필드도 올바르게 수정합니다.

    Args:
        file_path (str): 원본 PE 파일 경로
        output_file (str): 수정된 PE 파일 저장 경로
        increase_size (int): 섹션 크기를 늘릴 바이트 수
        nop_count (int): 섹션 끝에 추가할 NOP 바이트 수
    """
    try:
        # PE 파일 로드
        pe = lief.parse(file_path)
        if not pe or not hasattr(pe, 'optional_header'):
            print(f"[ERROR] The file '{file_path}' is not a valid PE file or does not have an optional header.")
            return False

        # FileAlignment 및 SectionAlignment 가져오기
        file_alignment = pe.optional_header.file_alignment
        section_alignment = pe.optional_header.section_alignment

        print(f"[INFO] FileAlignment: {file_alignment}, SectionAlignment: {section_alignment}")

        # 각 섹션 크기 및 섹션 헤더 수정
        previous_end_of_file = 0
        for section in pe.sections:
            print(f"[INFO] Processing section: {section.name}")

            # 파일 크기 (SizeOfRawData) 증가 및 정렬
            raw_size = section.size + increase_size
            new_raw_size = (raw_size + file_alignment - 1) // file_alignment * file_alignment
            section.size = new_raw_size
            print(f"  [INFO] New SizeOfRawData: {new_raw_size} (aligned from {raw_size})")

            # 메모리 크기 (VirtualSize) 증가 및 정렬
            virtual_size = section.virtual_size + increase_size
            new_virtual_size = (virtual_size + section_alignment - 1) // section_alignment * section_alignment
            section.virtual_size = new_virtual_size
            print(f"  [INFO] New VirtualSize: {new_virtual_size} (aligned from {virtual_size})")

            # 섹션 데이터 오프셋(PointerToRawData) 업데이트
            if previous_end_of_file == 0:
                previous_end_of_file = section.offset + new_raw_size
            else:
                section.offset = previous_end_of_file
                previous_end_of_file += new_raw_size
            print(f"  [INFO] Updated PointerToRawData: {section.offset}")

            # 섹션 끝에 NOP (0x90) 추가 + 패딩 적용
            section_data = list(section.content)  # 기존 섹션 데이터
            section_data.extend([0x90] * nop_count)  # NOP 추가
            padding_size = section.size - len(section_data)  # 부족한 크기 계산
            if padding_size > 0:
                section_data.extend([0x00] * padding_size)  # 부족한 부분을 0x00 패딩
            section.content = section_data  # 다시 content에 반영

            print(f"  [INFO] Added {nop_count} NOP (0x90) and {padding_size} bytes padding to section: {section.name}")

        # SizeOfImage 업데이트
        last_section = pe.sections[-1]
        new_size_of_image = last_section.virtual_address + last_section.virtual_size
        pe.optional_header.sizeof_image = new_size_of_image
        print(f"[INFO] Updated SizeOfImage: {new_size_of_image}")

        # 수정된 파일 저장 (PE Builder 사용)
        builder = lief.PE.Builder(pe)
        builder.build()
        builder.write(output_file)
        print(f"[SUCCESS] Modified file saved to: {output_file}")

        return True

    except Exception as e:
        print(f"[ERROR] {e}")
        return False

def process_sample(args):
    sample, root, save_dir, increase_size, nop_count = args
    input_filepath = os.path.join(root, sample)
    output_filename = sample.replace('.exe', '_increase.exe')
    output_filepath = os.path.join(save_dir, output_filename)

    #이미 파일이 존재하는 경우 건너뜀
#     if os.path.isfile(output_filepath):
#         return

    try:
        increase_section_size_with_nop(input_filepath, output_filepath, increase_size, nop_count)

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
#     save_dir_base = '../sample/perturbated_labling_sample/increase_section/'
    
#     sample_dir = '../sample/perturbated_labling_sample/resource_change/'
#     save_dir_base = '../sample/perturbated_labling_sample/resource_change+increase_section/'
    
#     sample_dir = '../sample/perturbated_labling_sample/instruction_change/'
#     save_dir_base = '../sample/perturbated_labling_sample/instruction_change+increase_section/'
    
    sample_dir = '../sample/perturbated_labling_sample/instruction_change+resource_change/'
    save_dir_base = '../sample/perturbated_labling_sample/all/'
    
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

#     sample_dir = '../sample/sample_AE/instruction_change/'
#     save_dir_base = '../sample/sample_AE/increase_section+instruction_change/'
    
#     sample_dir = '../sample/sample_AE/resource_change+instruction_change/'
#     save_dir_base = '../sample/sample_AE/all/'
    
    tasks = []
    
    increase_size=1
    nop_count=5
    
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
            #if 'iexplore_32_changing.exe' not in sample:
            #if 'hello_world.exe' not in sample:
            #if 'putty.exe' not in sample:
            #if 'bd9d7c4f16e03dc6a3485d01ea308039ccf96597e807f65912e147420270eba5' not in sample:
                #continue
            if any(ext in sample for ext in ['.ipynb', '.pickle', '.txt', '.zip','_tmp']):# or '.' not in sample:
                continue

            tasks.append((sample, root, save_dir, increase_size, nop_count))

    num_processes = max(1, multiprocessing.cpu_count() // 2)

    # 멀티프로세싱 Pool을 사용하여 작업 병렬 실행
    with multiprocessing.Pool(processes=num_processes) as pool:
        pool.map(process_sample, tasks)

    print("All tasks are completed.")

if __name__ == '__main__':
    main()