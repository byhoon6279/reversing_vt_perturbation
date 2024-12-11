import shutil
import os
import subprocess
import pefile
import re
from collections import Counter

def find_section_by_size(pe, target_size):
    for section in pe.sections:
        section_size = section.SizeOfRawData  # 섹션의 크기를 확인
        if section_size == int(target_size):
            return section.Name.decode('utf-8', errors='ignore').strip()
        else:
            pass
        
    return '.Not_found_section'

def find_hex_in_sections(file_path, hex_code):
    print()
    hex_bytes = bytes.fromhex(hex_code)

    # PE 파일 열기
    pe = pefile.PE(file_path)

    # 섹션에서 데이터 검색
    for section in pe.sections:
        section_data = section.get_data()
        index = section_data.find(hex_bytes)
        if index != -1:
            return section.Name.decode('utf-8', errors='ignore').strip()

    # 오버레이 계산
    with open(file_path, "rb") as f:
        f.seek(0, os.SEEK_END)
        file_size = f.tell()  # 파일 크기 계산

    last_section = pe.sections[-1]
    last_section_end = last_section.PointerToRawData + last_section.SizeOfRawData

    # 오버레이 시작 위치와 끝 위치 비교
    if file_size > last_section_end:
        overlay_size = file_size - last_section_end

        # 오버레이 데이터 읽기
        with open(file_path, "rb") as f:
            f.seek(last_section_end)
            overlay_data = f.read(overlay_size)

        # 오버레이에서 hex_code 검색
        if overlay_data.find(hex_bytes) != -1:
            return ".Overlay"
    else:
        overlay_size = 0  # 오버레이가 없는 경우

    print(f"Overlay size: {overlay_size} bytes")
    return '.Not_found'


def generate_regex_from_pattern(hex_code):
    # {} 안에 있는 숫자 범위를 처리
    def handle_braces(match):
        content = match.group(1)
        if '-' in content:
            parts = content.split('-')
            # 빈 값을 확인하고 기본값(0 또는 적절한 값)으로 대체
            if not parts[0].isdigit():
                parts[0] = "0"  # 기본값 0
            if not parts[1].isdigit():
                parts[1] = "0"  # 기본값 0
            min_val, max_val = map(int, parts)
            return f".{{{min_val*2},{max_val*2}}}"  # 정규 표현식: {min,max}로 변환
        elif content.isdigit():
            count = int(content)
            return f".{{{count*2}}}"  # 정규 표현식: {count}로 변환
        else:
            raise ValueError(f"Invalid format in braces: {content}")

    # '{}' 내부를 숫자 범위 또는 숫자로 변환
    pattern = re.sub(r'\{(-?\d+(?:-\d+)?)\}', handle_braces, hex_code)
    #print(pattern)

    # 와일드카드 ?와 *을 정규 표현식으로 변환
    pattern = pattern.replace('?', '.').replace('*', '.*').lower()
    return re.compile(pattern)  # 정규식 객체 반환

def find_hex_with_single_wildcard_in_sections(pe, hex_code):
    regex = generate_regex_from_pattern(hex_code)

    for section in pe.sections:
        section_data = section.get_data()
        section_hex = section_data.hex()  # 섹션 데이터를 hex 문자열로 변환

        # 정규식 검색
        match = regex.search(section_hex)
        if match:
            # 매칭된 데이터를 반환
            matched_data = match.group()  # decode() 제거
            return section.Name.decode('utf-8', errors='ignore').strip(), matched_data

    return '.Not_found_section', None

def main(input_dir, output_file):
    
    check_list = []
    sig_cnt = 0
    section_list = []
    
    with open(input_dir, "r", encoding="utf-8") as file:
        content = file.read()

    content = content.split('\n')
    for line in content:
        if not line:
            break
            
#         if 'Win.Trojan.Fareit-68' not in line:
#             continue
            
        with open(output_file, "a",  encoding="utf-8") as f:
            if 'OK' not in line and '.exe' in line:
                file_path = line.split(':')[0].strip()
                pe = pefile.PE(file_path)

                label = line.split(':')[-1].replace(' FOUND','').strip()
                
                if label in check_list:
                    continue

                check_list.append(label)
                #f.write(f'{label}\n')  # 파일에 쓰기
                #print(label)
                
                if label.startswith('BC.'):
                    label = re.sub(r'\.A$', '', label) 
                    

                result = subprocess.check_output(f'sigtool --find-sigs="{label}"', shell=True)
                sig = result.decode('utf-8')  # 바이트 값을 문자열로 변환
                sig = sig.strip().splitlines()
#                 print(result)
#                 sig_type = sig[0].split('] ')[0] +']'
#                 new_label = sig_type+' '+label
#                 #print(label)
#                 f.write(f'{new_label}\n')  # 파일에 쓰기
#                 print(new_label)

                if len(sig)>1:
                    try:
                        index = [i for i, item in enumerate(sig) if label == item.split(':')[-1]] 
                        sig = sig[index[0]]
                    except IndexError:
                        index = [i for i, item in enumerate(sig) if label == item.split(':')[0].split(' ')[-1]]
                        sig = sig[index[0]]
                else:
                    sig = sig[-1]
            
                
                #print("sig : ",sig)
                if isinstance(sig, list):
                    sig_type = sig[0].split('] ')[0] +']'
                else:
                    sig_type = sig.split('] ')[0] +']'
                    
                new_label = sig_type+' '+label
                #print(label)
                f.write(f'{new_label}\n')  # 파일에 쓰기
                print(new_label)
                    
                if '.ldb' in sig:
                    sig_list = sig.split(';')
                    sig = sig_list[0]+';'+sig_list[1]+';'+sig_list[2]
                    print(sig)
                    sig_list = sig_list[3:]
                    print(sig_list)
                    for part in sig_list:
                        part = part.lower().strip()
                        if '::w' in part:
                            hex_part = part.replace('::w','')
                            new_hex_string = ""

                            for i in range(0, len(hex_part), 2):
                                # 2바이트씩 끊기
                                split_part = hex_part[i:i+2]
                                # 뒤에 00 추가
                                new_hex_string += split_part + "00"   

                            section = find_hex_in_sections(file_path, new_hex_string)
                            section = section.rstrip('\x00')
                            try:
                                f.write(f'{part} - {bytes.fromhex(new_hex_string).decode("utf-8")} - {section} \n')  # 파일에 쓰기
                                print(part, ' - ',bytes.fromhex(new_hex_string).decode('utf-8'), ' - ',section)
                            except UnicodeDecodeError:
                                f.write(f'{part} - {"Unreadable_content"} - {section} \n')  # 파일에 쓰기
                                print(part, ' - ',"Unreadable_content", ' - ',section)
                                
                            sig_cnt+=1
                            section_list.append(section)
                        else:
                            #print("hi : ",part)
                            
                            if '::' in part:
                                part = part.split('::')[0]

                            if '?' in part or '*' in part or '{' in part:
                                ori_part = part
                                section, part = find_hex_with_single_wildcard_in_sections(pe, part)
                                section = section.rstrip('\x00')
                                
                                if not part:
                                    #print(part)
                                    print(ori_part, ' - None -  ',section)
                                    f.write(f'{ori_part} - {"None"} - {section} \n')  # 파일에 쓰기
                                else:
                                    try:
                                        print(part, ' - ',bytes.fromhex(str(part)).decode('utf-8'), ' - ',section)
                                        f.write(f'{part} - {bytes.fromhex(str(part)).decode("utf-8")} - {section} \n')  # 파일에 쓰기
                                        
                                    except UnicodeDecodeError:
                                        f.write(f'{part} - {"Unreadable_content"} - {section} \n')  # 파일에 쓰기
                                        print(part, ' - ',"Unreadable_content", ' - ',section)
                                    
                                sig_cnt+=1
                                section_list.append(section)
                            else:
                                
                                section = find_hex_in_sections(file_path, part)
                                section = section.rstrip('\x00')
                                try:
                                    print(part, ' - ',bytes.fromhex(part).decode('utf-8'), ' - ',section)
                                    f.write(f'{part} - {bytes.fromhex(part).decode("utf-8")}  - {section}\n')  # 파일에 쓰기
                                except UnicodeDecodeError:
                                    f.write(f'{part} - {"Unreadable_content"} - {section} \n')  # 파일에 쓰기
                                    print(part, ' - ',"Unreadable_content", ' - ',section)
                                    
                                #print(part, ' - ',bytes.fromhex(part).decode('utf-8'), ' - ',section)
                                sig_cnt+=1
                                section_list.append(section)
                    print('-' * 50)
                    f.write('-' * 50 + '\n')  # 구분선 파일에 쓰기


                if '.ndb' in sig :
                    sig_list = sig.split(':')[2:]
                    print(sig.split(':')[0])
                    #print(sig_list)
                    #sig = sig_list[2]+':'+sig_list[1]+';'+sig_list[2]
                    for part in sig_list:
                        part = part.lower().strip()
                        
                        print(part)

                        #if '+' in part or (len(part) == 1 and '*' == part) or (len(part) % 2 != 0 or not all(c in '0123456789abcdefABCDEF?*{}-' for c in part)):
                        if '+' in part or (len(part) == 1 and '*' == part) or (not all(c in '0123456789abcdefABCDEF?*{}-' for c in part)) or part.isdigit():
                            continue

                            
                        print(part)

                        if '?' in part or '*' in part or '{' in part:
                            section, part = find_hex_with_single_wildcard_in_sections(pe, part)
                            section = section.rstrip('\x00')
                            try:
                                print(part, ' - ',bytes.fromhex(str(part)).decode('utf-8'), ' - ',section)
                                f.write(f'{part} - {bytes.fromhex(str(part)).decode("utf-8")} - {section} \n')  # 파일에 쓰기
                                
                            except UnicodeDecodeError:
                                f.write(f'{part} - {"Unreadable_content"} - {section} \n')  # 파일에 쓰기
                                print(part, ' - ',"Unreadable_content", ' - ',section)
                            sig_cnt+=1
                            section_list.append(section)
                            
                        else:
                            section = find_hex_in_sections(file_path, part)
                            section = section.rstrip('\x00')
                            try:
                                print(part, ' - ',bytes.fromhex(part).decode('utf-8'), ' - ',section)
                                f.write(f'{part} - {bytes.fromhex(part).decode("utf-8")}  - {section}\n')  # 파일에 쓰기
                                                            
                            except UnicodeDecodeError:
                                f.write(f'{part} - {"Unreadable_content"} - {section} \n')  # 파일에 쓰기
                                print(part, ' - ',"Unreadable_content", ' - ',section)
                                
                            sig_cnt+=1
                            section_list.append(section)
                    print('-' * 50)      
                    f.write('-' * 50 + '\n')  # 구분선 파일에 쓰기

                if '.mdb' in sig:
                    sig = sig.split(' ')[-1]
                    section_size = sig.split(':')[0]
                    print(sig)
                    section = find_section_by_size(pe,section_size)
                    section = section.rstrip('\x00')
                    f.write(f'{section_size} - {"Section_hash_Signature"} - {section} \n')  # 파일에 쓰기
                    print(section_size, ' - ',"Section_hash_Signature", ' - ',section)
                    sig_cnt+=1
                    section_list.append(section)
                    print('-' * 50)      
                    f.write('-' * 50 + '\n')  # 구분선 파일에 쓰기
                    continue

                if '.hdb' in sig or '.hsb' in sig:
                    sig = sig.split(' ')[-1]
                    section_size = sig.split(':')[1]
                    print(sig)
                    #f.write(f'{sig}\n')
                    f.write(f'{section_size} - {"File_hash_Signature"} - {".File hash"} \n')  # 파일에 쓰기
                    print(section_size, ' - ',"File_hash_Signature", ' - ',".File hash")
                    sig_cnt+=1
                    print('-' * 50)      
                    f.write('-' * 50 + '\n')  # 구분선 파일에 쓰기
                    continue

                if 'BYTECODE' in sig:
                    sig_list = sig.split(';')
                    sig = sig_list[0]+';'+sig_list[1]+';'+sig_list[2]
                    print("else : ",sig)
                    f.write(f'{sig}\n')
                   
                    sig_list = sig_list[3:]
                    
                    for part in sig_list:
                        part = part.lower().strip()
                        if '?' in part or '*' in part or '{' in part:
                            ori_part = part
                            section, part = find_hex_with_single_wildcard_in_sections(pe, part)
                            section = section.rstrip('\x00')
                            try:
                                print(part, ' - ',bytes.fromhex(str(part)).decode('utf-8'), ' - ',section)
                                f.write(f'{part} - {bytes.fromhex(str(part)).decode("utf-8")} - {section} \n')  # 파일에 쓰기
                                sig_cnt+=1
                                section_list.append(section)
#                                 print('-' * 50)      
#                                 f.write('-' * 50 + '\n')  # 구분선 파일에 쓰기
                                
                            except ValueError:
                                print(ori_part, ' - Too_long_content - ',section)
                                f.write(f'{ori_part} -Too_long_content - {section} \n')  # 파일에 쓰기
                                sig_cnt+=1
                                section_list.append(section)
                            
                        else:
                            section = find_hex_in_sections(file_path, part)
                            section = section.rstrip('\x00')
                            try:
                                print(part, ' - ',bytes.fromhex(str(part)).decode('utf-8'), ' - ',section)
                                f.write(f'{part} - {bytes.fromhex(str(part)).decode("utf-8")} - {section} \n')  # 파일에 쓰기
                                sig_cnt+=1
                                section_list.append(section)
                                
                            except ValueError:
                                print(ori_part, ' - Too_long_content - ',section)
                                f.write(f'{ori_part} -Too_long_content - {section} \n')  # 파일에 쓰기
                                sig_cnt+=1
                                section_list.append(section)
                    print('-' * 50)      
                    f.write('-' * 50 + '\n')  # 구분선 파일에 쓰기
    return sig_cnt, section_list

if __name__ == '__main__':
   
    input_dir = '../malware.txt'
    output_file='../find_sig.txt'
    
    # Output 파일이 이미 존재하면 삭제
    if os.path.exists(output_file):
        os.remove(output_file)
        print(f"Existing file '{output_file}' has been deleted.")
        
    sig_cnt, section_list = main(input_dir, output_file)        
    
    print("sig_cnt : ",sig_cnt)
    print("section_list : ",Counter(section_list))
    
        
        
        
        