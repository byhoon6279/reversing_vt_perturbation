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
    
def section_increase(args):
    sample, root, save_dir = args
    increase_size = 1
    nop_count  = 5
    input_filepath = os.path.join(root, sample)
    output_filename = sample.replace('.exe', '|section_increase.exe')
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
    sample = "putty.exe"
    root = "./"
    save_dir = "./temp/"
    
    increase_size=1
    nop_count=5
    
    process_sample((sample, root, save_dir))