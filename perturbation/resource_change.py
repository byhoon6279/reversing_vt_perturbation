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
from common_function import *
import multiprocessing

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

def is_utf16le_string(data, start):
    """UTF-16 LE 문자열인지 확인"""
    # UTF-16 LE 문자열은 각 문자 사이에 0x00이 있어야 합니다.
    length = len(data)
    for i in range(start, length, 2):
        if i + 1 >= length or data[i+1] != 0x00:
            return False
        if data[i] == 0x00 and data[i+1] == 0x00:  # 문자열의 끝을 의미
            break
    return True

def decode_utf16le_string(data, start):
    """UTF-16 LE 문자열을 디코딩"""
    end = start
    utf16le_str = []
    while end < len(data) and data[end] != 0x00:
        utf16le_str.append(chr(data[end]))
        end += 2  # 2바이트씩 증가
    return ''.join(utf16le_str), end + 2  # 마지막 null 문자를 넘겨야 함

def modify_data_sections(section_name = None, data = None , function_list = None):
    
    modified_data = bytearray(data)
    i = 0
    letters_set = (string.ascii_lowercase + string.digits) * 5

    with open('./api.pickle', "rb") as fw:
        api_list = pickle.load(fw)
        
    while i < len(modified_data):
        try:
            if is_printable(modified_data[i]):
                start = i
                
                # UTF-16 LE 문자열인지 확인
                if is_utf16le_string(modified_data, start):
                    utf16_text, end = decode_utf16le_string(modified_data, start)
                    
                    if  (
                            (re.findall(r'(%[-+0# ]*\d*(?:\.\d+)?[diuoxXfFeEgGaAcspn])', utf16_text)) 
                            or 
                            (
                                re.findall(r'\b[a-zA-Z0-9][a-zA-Z0-9\s\.,;:!?\'"()\[\]{}<>-]{5,}\b', utf16_text)  
                                and not re.findall(r'[-+#/\?^@\"※~ㆍ』;*%\{\}\<\>‘|\[\]`\'…》\”\“\’·$=_:&]', utf16_text)
                            ) 
                            or 
                            (
                                '\\' in utf16_text 
                                and len(utf16_text) > 5 
                                and not re.findall(r'[-+,#/\?^@\"※~ㆍ!』;*%\{\}\<\>‘|\(\)\[\]`\'…》\”\“\’·$=_:.&]', utf16_text) 
                                and not re.findall(r'[0-9]+', utf16_text)
                            )
                            or 
                            (
                                re.findall(r'(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}', utf16_text) 
                                and not re.findall(r'<[^>]+>', utf16_text) 
                                and not re.findall(r'=', utf16_text)
                            )
                        ):

                        
                        if len(modified_data[start:end]) <= len(letters_set):
                            random_list = random.sample(letters_set, len(modified_data[start:end]))
                        else:
                            random_list = random.choices(letters_set, k=len(modified_data[start:end]))
                    
                        modified_text = ''.join(random_list)
                        modified_utf16_data = bytearray(modified_text.encode('utf-16le'))
                        
                    else:
                        # 그렇지 않은 경우, 원래 데이터를 유지
                        modified_utf16_data = modified_data[start:end]
                    
                    modified_data[start:end] = modified_utf16_data
                    i = end
                    continue
                
                
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
                    
                                    
                elif (
                        # 'image', 'plain-text', 'audio', 'html' 문자열이 txt_type에 포함된 경우
                        'image' in txt_type or 'plain-text' in txt_type or 'audio' in txt_type or 'html' in txt_type 

                        # 또는 포맷 문자열(%d, %f 등)이 포함된 경우 또는 5자 이상의 영숫자와 특정 기호가 포함된 경우
                        or (
                            re.findall(r'(%[-+0# ]*\d*(?:\.\d+)?[diuoxXfFeEgGaAcspn])', text)  # 포맷 문자열 검사
                            or 
                            (  # 영숫자 및 특정 기호들이 5자 이상인 경우
                                re.findall(r'\b[a-zA-Z0-9][a-zA-Z0-9\s\.,;:!?\'"()\[\]{}<>-]{5,}\b', text) 
                                and not re.findall(r'[-+#/\?^@\"※~ㆍ』;*%\{\}\<\>‘|\[\]`\'…》\”\“\’·$=:&]', text)  # 특정 특수 문자가 없는지 확인
                            )
                        )

                        # 또는 백슬래시(\)가 포함되어 있고, 길이가 5자 이상이며 특정 특수 문자와 숫자가 포함되지 않은 경우
                        or (
                            '\\' in text 
                            and len(text) > 5 
                            and not re.findall(r'[-+,#/\?^@\"※~ㆍ!』;*%\{\}\<\>‘|\(\)\[\]`\'…》\”\“\’·$=_:.&]', text)  # 특정 특수 문자가 없는지 확인
                            and not re.findall(r'[0-9]+', text)  # 숫자가 없는지 확인
                        )

                        # 또는 도메인 패턴을 포함한 텍스트
                        or (
                            re.findall(r'(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}', text)  # 도메인 패턴 (예: example.com)
                            and not re.findall(r'<[^>]+>', text)  # HTML 태그가 없는지 확인
                            and not re.findall(r'=', text)  # 등호(=)가 없는지 확인
                        )
                    ):
        
                    format_specifier = ''
                    
                    if text in api_list:
                        #print("api?? : ",text)
                        modified_text = modified_data[start:end]
                        modified_text = bytes(modified_text)
                        modified_data[start:end] = modified_text
                        continue
                        
                    if len(text)>5 and re.findall(r'(%[-+0# ]*\d*(?:\.\d+)?[diuoxXfFeEgGaAcspn])',text):
                        format_specifier = re.findall(r'(%[-+0# ]*\d*(?:\.\d+)?[diuoxXfFeEgGaAcspn])',text)[0]
                        last_text= text.split(format_specifier)[-1]
                        text = text.split(format_specifier)[0]
                        
                        format_specifier = format_specifier + last_text

                    if len(text) <= len(letters_set):
                        random_list = random.sample(letters_set, len(text))
                    else:
                        random_list = random.choices(letters_set, k=len(text))
                    

                    modified_text = ''.join(random_list)
                    
                    if format_specifier:
                        modified_text = modified_text+format_specifier
                        
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

            if section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_CNT_INITIALIZED_DATA'] and \
                section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_READ'] or \
                section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_WRITE']:
                
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

        # 오버레이 영역 검사
        last_section_end = pe.sections[-1].PointerToRawData + pe.sections[-1].SizeOfRawData
        if len(pe_data) > last_section_end:
            overlay_data = pe_data[last_section_end:]
            print("Overlay data detected and will be processed.")
            modified_overlay_data = modify_data_sections("overlay", overlay_data, function_list)
            modified_data += modified_overlay_data

    except Exception as e:
        print(f"Error in processing PE file: {str(e)}")

    # 변경된 파일 저장
    output_file = os.path.join(output_path, os.path.basename(file_path))
    with open(output_file, "wb") as f:
        f.write(modified_data)

    pe.close()
    
#----------------------------------------------------single_processing_main_function  
# if __name__ == "__main__":
    
# #     sample_dir = '../evaluation//clamav/adding_nop_100/'
# #     save_dir = '../evaluation/clamav/adding_nop_100+resource_change_involve_data/'
    
#     sample_dir = '../sample/benign/'
#     save_dir = '../evaluation/perturbated_sample_benign/'
    
#     samples = list_files_by_size(sample_dir)
#     create_directory(save_dir)

#     for sample in samples:
        
# #         if '620bae1ab9de6fa46fe9eae40169f00e74374d9df32bc87c1a6a2954a70a6dce_nop_fin_100' not in sample:
# #             continue

# #         if '.ipynb_checkpoints' in sample or ('.exe' not in sample and '.dll' not in sample): #or 'calc' not in sample:)
# #             continue
#         try:   
#             change_resource_case(sample_dir+sample, save_dir)
#             print(f"Resource case changed for {sample}","\n")
#             #print(sample_dir+sample, save_dir)
            
#         except pefile.PEFormatError:
#             continue
            
#         except ValueError: # 샘플 확인 -> 현재는 ValueError 나는 샘플 없음
#             continue


#----------------------------------------------------multi_processing_main_function        
def process_sample(args):
    sample, root, save_dir = args
    file_path = os.path.join(root, sample)
#     output_filename_1 = sample.replace('.exe', '_adding_'+str(number_of_nop)+'.exe')
#     output_filename_2 = sample.replace('.exe', '_nop_fin_'+str(number_of_nop)+'.exe')
#     output_filepath_1 = os.path.join(save_dir, output_filename_1)
#     output_filepath_2 = os.path.join(save_dir, output_filename_2)

#     if os.path.isfile(output_filepath_1) or os.path.isfile(output_filepath_2):
#         return

    try:
        change_resource_case(file_path, save_dir)
        print(f"Resource case changed for {sample}\n")
        
    except pefile.PEFormatError:
        pass      

def main():
#     sample_dir = '../sample/labeling/'
#     save_dir_base = '../sample/perturbated_labling_sample/resource_change/'

#     sample_dir = '../sample/perturbated_labling_sample/instruction_change/'
#     save_dir_base = '../sample/perturbated_labling_sample/instruction_change+resource_change/'
    
#     sample_dir = '../sample/perturbated_labling_sample/adding_nop/'
#     save_dir_base = '../sample/perturbated_labling_sample/adding_nop+resource_change/'
    
#     sample_dir = '../sample/perturbated_labling_sample/adding_nop+instruction_change/'
#     save_dir_base = '../sample/perturbated_labling_sample/adding_nop+instruction_change+resource_change/'
    
    sample_dir = '../sample/perturbated_labling_sample/instruction_change+adding_nop_partial/'
    save_dir_base = '../sample/perturbated_labling_sample/instruction_change+adding_nop_partial+resource_change/'
    
    tasks = []

    for root, dirs, files in os.walk(sample_dir):
        if 'ok' in root.split(os.sep):
            continue

#         if len(files) <= 10:
#             continue
        
        save_dir = os.path.join(save_dir_base, os.path.basename(root))
        create_directory(save_dir + '/')
        
        for sample in list_files_by_size(root):
            if any(ext in sample for ext in ['.ipynb', '.pickle', '.txt', '.zip']) or '.' not in sample:
                continue
                
            tasks.append((sample, root, save_dir))

    num_processes = max(1, multiprocessing.cpu_count() // 2)

    with multiprocessing.Pool(processes=num_processes) as pool:
        pool.map(process_sample, tasks)

    print("All tasks are completed.")

if __name__ == '__main__':
    main()        