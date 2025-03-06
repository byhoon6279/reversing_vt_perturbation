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

def assemble_asm(asm_code, arch, mode, big_endian=False):
    # 아키텍처와 모드에 맞게 Keystone 인스턴스 생성
    ks = Ks(arch, mode)
    
    # 어셈블리 코드를 머신 코드로 변환
    encoding, count = ks.asm(asm_code)
    
    # 변환된 머신 코드를 반환
    return encoding

def create_enum_dict(module: ModuleType) -> Dict[int, str]:
    return {module.__dict__[key]:key for key in module.__dict__ if isinstance(module.__dict__[key], int)}

CODE_TO_STRING: Dict[Code_, str] = create_enum_dict(Code)
def code_to_string(value: Code_) -> str:
    s = CODE_TO_STRING.get(value)
    if s is None:
        return str(value) + " /*Code enum*/"
    return s

def modify_headers(file_path, new_text, fin = None):
    pe = pefile.PE(file_path)
    file_format = '.'+file_path.split('.')[-1]

    # Find the .text section
    text_section = None
    for section in pe.sections:
        if section.Name.strip(b'\x00').lower() == b'.text' or section.Name.strip(b'\x00').upper() == b'CODE':
            text_section = section
            break

    if text_section is None:
        print("Error: .text section not found")
        return

    text_section.Misc = len(new_text)
    new_size = int((len(new_text) + pe.OPTIONAL_HEADER.FileAlignment - 1) / pe.OPTIONAL_HEADER.FileAlignment) * pe.OPTIONAL_HEADER.FileAlignment
    new_text = new_text + b'\x00' * (new_size - len(new_text))

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

    pe.write(filename=file_path.replace(file_format, "_tmp"+file_format))
    pe.close()
    return new_text

def create_directory(path):
    try:
        os.makedirs(path, exist_ok=True)  # exist_ok=True 옵션을 사용하면 이미 디렉토리가 존재할 경우 예외가 발생하지 않습니다.
        print(f"Directory '{path}' created successfully.")
    except OSError as error:
        print(f"Error creating directory '{path}': {error}")
        
def list_files_by_size(directory):
    try:
        # Get list of files in the directory along with their sizes
        files = [(file, os.path.getsize(os.path.join(directory, file))) for file in os.listdir(directory) if os.path.isfile(os.path.join(directory, file))]
        
        # Sort the list of files by their size
        sorted_files = sorted(files, key=lambda x: x[1])
        
        return [file for file, size in sorted_files]
        
    except Exception as e:
        print(f"Error: {e}")