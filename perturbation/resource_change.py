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
from identify import identify
import pickle
from functools import lru_cache

old_rawPointer = 0
modified_section_data = {}

@lru_cache(maxsize=None)
def get_imported_functions(pe):
    imported_functions = []
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('utf-8')
            for imp in entry.imports:
                if imp.name:
                    function_name = imp.name.decode('utf-8')
                    offset = imp.address - pe.OPTIONAL_HEADER.ImageBase
                    imported_functions.append(function_name)
    return imported_functions

@lru_cache(maxsize=None)
def get_exported_functions(pe):
    exported_functions = []
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                function_name = exp.name.decode('utf-8')
                offset = exp.address - pe.OPTIONAL_HEADER.ImageBase

                exported_functions.append(function_name)
    return exported_functions

@lru_cache(maxsize=None)
def is_printable(b):
    return 32 <= b < 127

def modify_data_sections(section_name, data, function_list):
    section_names = [".rdata", ".idata", ".edata", ".rsrc", ".data", "data", "rdata", "idata", "edata", "rsrc"]

    modified_data = bytearray(data)
    i = 0
    letters_set = (string.ascii_lowercase + string.digits) * 5

    with open('./api.pickle', "rb") as fw:
        api_list = pickle.load(fw)
        
    while i < len(modified_data):
        try:
            if is_printable(modified_data[i]):
                start = i
                while i < len(modified_data) and is_printable(modified_data[i]):
                    i += 1
                end = i
                text = modified_data[start:end].decode('ascii', errors='ignore')                
                txt_type = identify.tags_from_filename(text.strip())

                if ('.dll' in text.lower() and 'binary' in txt_type) or ('.dll' in text.lower()):
                    text = text.split('.')[0]
                    if text.isupper():
                        new_text = text + '.dll'
                        modified_text = new_text.lower().encode('ascii')
                    else:
                        new_text = text + '.dll'
                        modified_text = new_text.upper().encode('ascii')
                    modified_data[start:end] = modified_text
                    continue

#                 elif 'image' in txt_type or 'plain-text' in txt_type or 'audio' in txt_type or 'html' in txt_type or (section_name in section_names and txt_type)\
#                         or ('\\' in text and len(text)>5 and not re.findall(r'[-+,#/\?^@\"※~ㆍ!』;*%\{\}\<\>‘|\(\)\[\]`\'…》\”\“\’·$=_:.&]',text) and len(text)>5 and not re.findall(r'[0-9]+',text)):
#                 elif 'image' in txt_type or 'plain-text' in txt_type or 'audio' in txt_type or 'html' in txt_type or (section_name in section_names and txt_type) or (re.findall(r'\b[a-zA-Z0-9][a-zA-Z0-9\s\.,;:!?\'"()\[\]{}<>-]{3,}\b',text)):
                elif 'image' in txt_type or 'plain-text' in txt_type or 'audio' in txt_type or 'html' in txt_type or (section_name in section_names and txt_type) or \
                        (re.findall(r'\b[a-zA-Z0-9][a-zA-Z0-9\s\.,;:!?\'"()\[\]{}<>-]{5,}\b',text) and not re.findall(r'[-+,#/\?^@\"※~ㆍ』;*%\{\}\<\>‘|\[\]`\'…》\”\“\’·$=_:.&]',text)) or \
                            ('\\' in text and len(text)>5 and not re.findall(r'[-+,#/\?^@\"※~ㆍ!』;*%\{\}\<\>‘|\(\)\[\]`\'…》\”\“\’·$=_:.&]',text) and len(text)>5 and not re.findall(r'[0-9]+',text)):

                    if text in api_list:
                        modified_text = modified_data[start:end]
                        modified_text = bytes(modified_text)
                        modified_data[start:end] = modified_text
                        continue

                    # 샘플링 크기를 letters_set 길이로 제한
                    if len(text) <= len(letters_set):
                        random_list = random.sample(letters_set, len(text))
                    else:
                        random_list = random.choices(letters_set, k=len(text))
                    
                    #print(text, random_list, section_name)
                    modified_text = ''.join(random_list)
                    modified_text = bytes(modified_text, 'utf-8')
                    modified_data[start:end] = modified_text
                    continue

                else:
                    modified_text = modified_data[start:end]
                    modified_text = bytes(modified_text)
                    modified_data[start:end] = modified_text
                    continue
            else:
                i += 1

        except Exception as e:
            print(f"Error processing text: {text}, section {section_name}: {str(e)}")
#             modified_text = modified_data[start:end]
#             modified_text = bytes(modified_text)
#             modified_data[start:end] = modified_text
            i = end  # i를 end로 설정하여 다음 블록으로 넘어가도록 함
            continue


    print(f"Returning modified data for section: {section_name}")
    return bytes(modified_data)



@lru_cache(maxsize=None)
def change_resource_case(file_path, output_path):
    pe = pefile.PE(file_path)
    pe_data = open(file_path, "rb").read()
    
    import_function = get_imported_functions(pe)
    export_function = get_exported_functions(pe)

    # 변경된 데이터를 저장할 변수
    modified_data = bytearray()

    # 섹션 데이터 소문자화 및 수정된 데이터 저장
    function_list = import_function + export_function

    try:
        for section_idx, section in enumerate(pe.sections):
            section_name = section.Name.decode().strip('\x00').lower()
            print(section_idx, section_name)
            
            if section_idx == 0:
                modified_data += pe.header
            
            if section_name in [".rdata", ".idata", ".edata", ".rsrc", ".data", "data", "rdata", "idata", "edata", "rsrc"]:
            #if section_name in [".rdata", ".idata", ".edata", ".rsrc", "rdata", "idata", "edata", "rsrc"]:
                print(f"Processing section: {section_name}")
                
                section_start = section.PointerToRawData
                section_end = section_start + section.SizeOfRawData
                
                section_data = pe_data[section_start:section_end]
                modified_rdata = modify_data_sections(section.Name.decode().strip('\x00'), section_data, function_list)
                print(f"Modified section data returned for {section_name}")

                # 중요한 부분: 수정된 데이터를 modified_data에 추가
                modified_data += modified_rdata
                
            else:
                print(f"Skipping section: {section_name}")
                section_start = section.PointerToRawData
                section_end = section_start + section.SizeOfRawData
                
                section_data = pe_data[section_start:section_end]
                modified_data += section_data

        if pe_data[section_end:]:
            last = pe_data[section_end:]
            modified_data += last

    except Exception as e:
        print(f"Error in processing PE file: {str(e)}")

    # 변경된 파일 저장
    output_file = os.path.join(output_path, os.path.basename(file_path))
    with open(output_file, "wb") as f:
        f.write(modified_data)

    pe.close()
    
if __name__ == "__main__":
    
    sample_dir = '../sample/input_sample/'
    save_dir = '../sample/perturbated_sample/resource_change/' 
    
    samples = list_files_by_size(sample_dir)
    create_directory(save_dir)

    for sample in samples:

        if '.ipynb_checkpoints' in sample or ('.exe' not in sample and '.dll' not in sample): #or 'calc' not in sample:)
            continue
            
        change_resource_case(sample_dir+sample, save_dir)
        print(f"Resource case changed for {sample}","\n")