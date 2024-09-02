import distorm3
import pefile
from pe_library import *
from iced_x86 import *
from typing import Union, Dict, Sequence 
from types import ModuleType
from keystone import *
import pickle
import shutil
import r2pipe
import mmap
from tqdm import tqdm
from common_function import *
from functools import lru_cache
import multiprocessing

old_rawPointer = 0
old_nextPointer = 0

# Helper function for memory mapping
def memory_map(filename):
    with open(filename, "r+b") as f:
        return mmap.mmap(f.fileno(), 0)
    
def modify_headers(file_path, new_text, fin=None):
    pe = pefile.PE(file_path)
    file_format = '.' + file_path.split('.')[-1]

    # Find the .text section
    text_section = None
    section_idx = 0
    
    for section in pe.sections:
        if b'.text' in section.Name.strip(b'\x00').lower():
            text_section = section
            break

    if text_section is None:
        print("Error: .text section not found")
        return

    new_text_data = new_text[section_idx]
    text_section.Misc = len(new_text_data)
    new_size = (len(new_text_data) + pe.OPTIONAL_HEADER.FileAlignment - 1) // pe.OPTIONAL_HEADER.FileAlignment * pe.OPTIONAL_HEADER.FileAlignment
    new_text_data += b'\x00' * (new_size - len(new_text_data))

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

    pe.write(filename=file_path.replace(file_format, "_tmp" + file_format))
    pe.close()
    return [new_text_data]

def modify_section(file_path, new_text, save_dir, number_of_nop, fin=None):
    global old_rawPointer
    global old_nextPointer
    
    file_format = '.' + file_path.split('.')[-1]
    tmp_file = file_path.replace(file_format, "_tmp" + file_format)

    with open(tmp_file, "rb") as tmp:
        tmp_binary = tmp.read()

    new_binary = tmp_binary[:old_rawPointer] + new_text[0] + tmp_binary[old_rawPointer + len(new_text[0]):]

    if fin:
        final_path = os.path.join(save_dir, file_path.split('/')[-1].replace(file_format, f"_nop_fin_{number_of_nop}{file_format}"))
    else:
        final_path = os.path.join(save_dir, file_path.split('/')[-1].replace(file_format, f"_adding_{number_of_nop}{file_format}"))

    with open(final_path, "wb") as f:
        f.write(new_binary)

    os.remove(tmp_file)

    return final_path

    
def modify_tramp(save_dir, modified_address, fin = None):

    file_path = save_dir
    pe = pefile.PE(file_path)
    pe_data = open(file_path, "rb").read()

    # .tramp 섹션 찾기
    section = next(section for section in pe.sections if  b'.Tram' in section.Name.rstrip(b'\x00'))

    image_base = pe.OPTIONAL_HEADER.ImageBase

    text_start = section.VirtualAddress + image_base
    text_end = text_start + section.Misc_VirtualSize

    binary_data = section.get_data()
    ori_binary_data = binary_data

    if pe.FILE_HEADER.Machine == 0x8664:
        bitness = 64

    else:
        bitness = 32

    decoded_instructions = decode_instructions(binary_data, text_start, bitness)
 
    array_offset = 0
    
    for (offset, size, instruction, hexdump) in decoded_instructions:
        if '90' not in hexdump:
            print(offset, hex(offset), size, instruction, hexdump)

            present_address = hex(offset)
            array_offset = offset
            instruction_len = size
            instruction = hexdump

            offset = to_little_endian(instruction[2:])
            int_operand = hex_to_signed_int(offset)

            target_address = instruction_len + int(present_address,16) + int_operand
            new_address = modified_address[target_address]

            new_offset = new_address - instruction_len - int(present_address,16)

            operand = hex(new_offset).replace('x','0',1)

            if len(operand)%2 !=0:
                new_operand = '0'+operand
                operand = new_operand

            operand = to_little_endian(operand)
            operand += '0' * (8-len(operand))

            if fin:
                print("Trampoline Address : ",hex(target_address),"-->",hex(new_address))
                print(".Tramp operand : ",operand,len(operand))

            new_value =  bytes.fromhex(('e9'+operand))

            break

    print(new_value)

    # 변경된 데이터를 PE 파일에 반영
    pe.set_bytes_at_offset(array_offset, new_value)

    output_file_path = file_path 
    pe.write(output_file_path)
    
def modify_rdata(save_dir, modified_address, fin = None):
    # PE 파일 로드
    file_path = save_dir
    pe = pefile.PE(file_path)

    # .rdata 섹션 찾기
    for section in pe.sections:
        #if section.Name.decode().strip('\x00').lower() in ['.data', '.rdata', 'data', 'const']: # add malware's custom section name if you want
        if section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_CNT_INITIALIZED_DATA'] and \
            section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_READ'] or \
            section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_WRITE']:

            section = section
            rdata_start = section.VirtualAddress
            rdata_end = rdata_start + section.Misc_VirtualSize
            section_size = section.SizeOfRawData
            section_start = section.PointerToRawData

            data = bytearray(pe.get_memory_mapped_image()[rdata_start:rdata_start + section_size])
            #print(data)

            # 절대 주소 필터링을 위한 범위 설정
            image_base = pe.OPTIONAL_HEADER.ImageBase
            text_section = next(section for section in pe.sections if  b'.text' in section.Name.strip(b'\x00').lower())
            text_start = text_section.VirtualAddress + image_base
            text_end = text_start + text_section.Misc_VirtualSize

            for i in range(0, section.Misc_VirtualSize, 4):
                value = int.from_bytes(pe.get_data(rdata_start + i, 4), byteorder='little')

                if text_start <= value < text_end:
                    # 절대 주소 수정
                    #try:
                    if value in modified_address:
                        #if modified_address[value]:
                        new_address = modified_address[value]
                        index = data.find(pe.get_data(rdata_start + i, 4))

                        if fin:
                            print("Modified Address : ", hex(value)," --> ",hex(new_address))

                        new_address = hex(new_address).replace('x','0',1)
                        new_address = to_little_endian(new_address)
                        pe.set_bytes_at_offset(section_start + index, bytes.fromhex(new_address))
                   # except:
                    else:
                        continue

    # 수정된 PE 파일 저장
    output_file_path = save_dir
    pe.write(output_file_path)
    print(f"Modified PE file saved as {output_file_path}")
    
    return output_file_path

@lru_cache(maxsize=128 )
def to_little_endian(hex_str):
    # 2자리씩 끊어서 리스트로 만듭니다.
    bytes_list = [hex_str[i:i+2] for i in range(0, len(hex_str), 2)]
    # 리스트를 역순으로 뒤집습니다.
    bytes_list.reverse()
    # 다시 문자열로 결합합니다.
    little_endian_str = ''.join(bytes_list)
    return little_endian_str
    
@lru_cache(maxsize=None)   
def should_add_nop(instruction):
    control_flow_instructions = [
        # 분기 명령어
        'jz', 'je', 'jnz', 'jne', 'js', 'jns', 'jo', 'jno', 'jc', 'jnc', 'jp', 'jpe', 'jnp', 'jpo', 'ja', 'jnbe', 'jae', 'jnb', 'jb', 
        'jnae', 'jbe', 'jna', 'jg', 'jnle', 'jge', 'jnl', 'jl', 'jnge', 'jle', 'jng', 'jcxz', 'jecxz', 'jrcxz', 'jmp',
        # 호출 및 리턴 명령어
        'call', 'ret', 'retf', 'iret', 'iretd', 'iretq',
        # 인터럽트 명령어
        'int', 'int3', 'into',
        # 제어 흐름 변경 명령어
        'loop', 'loope', 'loopne', 'syscall', 'sysret'
    ]

    opcode = instruction.split()[0].lower()
    return opcode not in control_flow_instructions

@lru_cache(maxsize=128)
def negative_to_little_endian_hex(negative_integer):
    # 음수를 32비트 2의 보수 16진수로 변환
    hex_string = hex(negative_integer & 0xFFFFFFFF)[2:]

    # 16진수 문자열을 8자리로 맞추기 위해 앞에 0을 추가
    hex_string = hex_string.zfill(8)

    # 16진수 문자열을 2자리씩 끊어서 리스트에 저장
    hex_bytes = [hex_string[i:i+2] for i in range(0, len(hex_string), 2)]

    # 바이트 순서를 반전하여 리틀 엔디안으로 변환
    little_endian_hex = ''.join(reversed(hex_bytes))

    return little_endian_hex

@lru_cache(maxsize=128)
def hex_to_signed_int(hex_str):
    value = int(hex_str, 16)
    if value & (1 << (len(hex_str) * 4 - 1)):
        value -= 1 << (len(hex_str) * 4)
    return value


def dict_to_frozenset(d):
    return frozenset(d.items())

@lru_cache(maxsize=None)
def decode_section_data(bit, section_data, addr):
    return list(Decoder(bit, section_data, ip=addr))

@lru_cache(maxsize=None)
def count_instructions(first_address, second_address, section_data, bit, number_of_nop, jump_dict, nop_cnt, increase_instr, pe_data, text_section, image_base, virtual_address):
    addr = image_base+virtual_address
    #decoder = Decoder(bit, section_data, ip=addr)
    decoder = decode_section_data(bit, section_data, addr)
    jump_dict = dict(jump_dict)
    
    instruction_count = 0
    increace_instruction =0
    increase_address = {}
    
    start_address = min(first_address, second_address)
    end_address = max(first_address, second_address)
            
    for instr in decoder:
        
        if (instr.ip < start_address):
            continue
            
        #else:
        if start_address <= instr.ip <= end_address:
            if instr.ip == end_address:
                break
            else:
                instr_str = str(instr)
                if any(x in instr_str for x in ('ret', 'int 3', 'nop')):
                    continue

                if not should_add_nop(str(instr)):
                    if len(instr)==2 and 'REL' in code_to_string(instr.code):
                       
                        present_instr = pe_data[text_section.PointerToRawData + (instr.ip-(image_base+virtual_address)):text_section.PointerToRawData + ((instr.next_ip)-(image_base+virtual_address))]
 
                        operand = present_instr.hex()[2:]

                        if 'ptr' in str(instr) and len(operand)>8:
                            operand = present_instr.hex()[4:]

                        address = hex(instr.ip+len(instr)+hex_to_signed_int(to_little_endian(operand))).replace('0x','',1).upper()   

                        anc = count_instructions_between_addresses(instr.ip, int(address,16), section_data, bit, (image_base+virtual_address), number_of_nop)

                        total_increase = calculate_instruction_length_increase(instr.ip, int(address,16), section_data, bit, dict_to_frozenset(jump_dict), dict_to_frozenset(increase_address), number_of_nop, pe_data, text_section, image_base, virtual_address)

                        offset = int(address,16) - instr.ip - len(instr)

                        operand = offset + anc + total_increase

                        if 0>offset:
                            operand = offset - anc - total_increase

                        #print("  ",hex(instr.ip), instr, operand, offset, anc, total_increase)
                        if operand<=(-128) or operand>=127:
                            increace_instruction+=1
                            op_code = str(instr).split(' ')[0]

                            new_ins_len = 5 if 'jmp' in op_code else 6
                           # print("  ",hex(instr.ip), instr, operand, offset, anc, total_increase)
                            increase_address[instr.ip] = int(new_ins_len - len(instr))
                    continue

                if instr.ip == end_address:
                    break

                if instr.ip == start_address:
                    instruction_count += (1*number_of_nop)
                    continue

                instruction_count += (1*number_of_nop)
                
    return instruction_count, increace_instruction, increase_address

@lru_cache(maxsize=None)
def count_instructions_between_addresses(first_address, second_address, section_data, bit, addr, number_of_nop):
    #decoder = Decoder(bit, section_data, ip=addr)
    decoder = decode_section_data(bit, section_data, addr)
         
    instruction_count_num = 0
    jump_counter = {}
    
    start_address = min(first_address, second_address)
    end_address = max(first_address, second_address)

    for instr in decoder:
        
        if (instr.ip < start_address):
            continue
            
        if start_address <= instr.ip <= end_address:
            if instr.ip == end_address:
                break

            else:
                instr_str = str(instr)
                if any(x in instr_str for x in ('ret', 'int 3', 'nop')):
                    continue

                if not should_add_nop(str(instr)):
                    op_code = str(instr).split(' ')[0]
                    new_ins_len = 5 if 'jmp' in op_code else 6
                    continue

                if instr.ip == end_address:
                    break

                if instr.ip == start_address:
                    instruction_count_num += (1*number_of_nop)
                    continue

                instruction_count_num += (1*number_of_nop)
    
    return instruction_count_num

@lru_cache(maxsize=None)
def calculate_instruction_length_increase(first_address, second_address, section_data, bit, jump_dict, increase_address, number_of_nop, pe_data, text_section, image_base, virtual_address):
    addr = image_base+virtual_address
    #decoder = Decoder(bit, section_data, ip=addr)
    decoder = decode_section_data(bit, section_data, addr)
    jump_dict = dict(jump_dict)
    increase_address = dict(increase_address)
    total_increase = 0
    
    start_address = min(first_address, second_address)
    end_address = max(first_address, second_address)

    for instr in decoder:
        
        if (instr.ip < start_address):
            continue
            
        if start_address <= instr.ip <= end_address:
            if instr.ip == end_address:
                break

            else:
                instr_str = str(instr)
                if any(x in instr_str for x in ('ret', 'int 3', 'nop')):
                    continue

                if not should_add_nop(str(instr)):


                    if len(instr)==2 and 'REL' in code_to_string(instr.code):
                       
                        present_instr = pe_data[text_section.PointerToRawData + (instr.ip-(image_base+virtual_address)):text_section.PointerToRawData + ((instr.next_ip)-(image_base+virtual_address))]
 
                        operand = present_instr.hex()[2:]

                        if 'ptr' in str(instr) and len(operand)>8:
                            operand = present_instr.hex()[4:]

                        address = hex(instr.ip+len(instr)+hex_to_signed_int(to_little_endian(operand))).replace('0x','',1).upper()   

                        offset = int(address,16) - instr.ip - len(instr)

                        anc = count_instructions_between_addresses(instr.ip, int(address,16), section_data, bit, addr, number_of_nop)

                        if number_of_nop ==1:
                            jmp_calibration = 0
                            calibration = 0
                        else:
                            jmp_calibration = sum(value for i, value in increase_address.items() if instr.ip <= i <= int(address,16))
                            calibration = sum(value for i, value in jump_dict.items() if start_address <= i <= end_address)

                        operand = offset+anc+calibration+jmp_calibration

                        if 0>offset:
                            operand = offset-anc-calibration-jmp_calibration

                        if operand<=(-128) or operand>=127:
                            op_code = str(instr).split(' ')[0]

                            new_ins_len = 5 if 'jmp' in op_code else 6

                            total_increase += int(new_ins_len - len(instr))
                    continue

                if instr.ip == end_address:
                    break

                if instr.ip == start_address:
                    continue
                   
    return total_increase

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
@lru_cache(maxsize=128)
def value_int_convert(value):
    value = list(value)
    value = value[0].replace('h','',1)
    value = value.replace(',','',1)
    hex_value = value.replace('[','',1).replace(']','',1)
    
    if '80' in hex_value:
        hex_value = value.replace('[','',1).replace(']','',1). replace('80','',1)
        
    value = int(hex_value,16)
    return value, hex_value

@lru_cache(maxsize=128)
def calc_offset(target_address, instr, ori_operand, op_code):
    if instr.ip > target_address:
        new_operand = target_address - instr.ip - len(instr)
        operand = negative_to_little_endian_hex(new_operand)

    if instr.ip < target_address:
        new_operand = target_address - instr.ip - len(instr)
        operand = hex(new_operand).replace('x','0',1) # target_address affset
        operand = operand.replace('00','',1)

        if len(ori_operand) - len(operand) != 0:
            new_operand = '0'* int(len(ori_operand) - len(operand))
            new_operand+= operand
            operand = new_operand

        operand = to_little_endian(operand)

    new_ins = op_code+operand

    return new_ins, op_code, operand 

@lru_cache(maxsize=128)
def hex_string_to_bytes(hex_string):
    # 입력 문자열에서 공백 제거 및 소문자 처리
    hex_string = hex_string.strip().upper()
    
    # 16진수 문자열을 바이트로 변환
    bytes_result = bytes.fromhex(hex_string)
    
    # 바이트 문자열을 반환
    return bytes_result

@lru_cache(maxsize=128)
def is_prefixes(hex_string):
    # 프리픽스 집합 정의
    prefixes = {
        '26', '2E', '36', '3E', '64', '65',  # Segment prefixes
        '66',  # Operand size override prefix
        '67',  # Address size override prefix
        'F0',  # Lock prefix
        'F2', 'F3'  # Repeat prefixes
    }
    
    # 입력된 문자열을 대문자로 변환
    hex_string = hex_string.upper()
    
    # 결과를 저장할 문자열
    result = hex_string
    removed_prefixes = []  
    
    # 프리픽스를 제거할 때 사용할 변수
    while len(result) > 2:
        # 앞의 2바이트 추출
        first_two_bytes = result[:2]
        remaining_bytes = result[2:]
        
        # 2바이트를 검사하여 프리픽스인지 확인
        if first_two_bytes in prefixes:
            # 프리픽스가 포함된 경우 제거
            removed_prefixes.append(first_two_bytes)
            result = remaining_bytes
        else:
            # 프리픽스가 없으면 반복 종료
            break
            
    removed_prefixes_str = ''.join(removed_prefixes)
    
    # 결과 반환: 지워진 프리픽스와 프리픽스가 지워진 문자열
    return hex_string_to_bytes(removed_prefixes_str), hex_string_to_bytes(result)

@lru_cache(maxsize=None)
def make_new_increase_instruction_operand(int_operand):
    parm_operand = hex(int_operand).replace('0x','',1)

    if len(parm_operand)%2 !=0:
        new_parm_operand = '0'+ parm_operand
        parm_operand = new_parm_operand

    new_operand = to_little_endian(parm_operand)

    operand = new_operand + '0' * (8-len(new_operand))
    
    return operand

                    
def minus_offset(offset, ori_operand):
   # print("  offset 1 : ",offset)
    operand = negative_to_little_endian_hex(offset)
    #print("  offset 2 : ",operand)
    operand = operand.replace('x','0',1)
   # print("  offset 3 : ",operand)

    while 1:
        if len(ori_operand) == len(operand):
            break
        else:
            operand = operand.replace('ff','',1)
   # print("  offset 4 : ",operand)
    return operand

def make_new_text(file_path ,number_of_nop):
    
    global old_rawPointer
    global old_nextPointer
        
    pe = pefile.PE(file_path)
    pe_data = open(file_path, "rb").read() 
    
    new_text_list = []
    
    jump_dict={}
    caller_callee_dict={}
    checking_target_address={}
    modified_address={}
    
    for section in pe.sections:
        #if section.Name.strip(b'\x00') == b'.text' or section.Name.strip(b'\x00').upper() == b'CODE':
        if (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_CNT_CODE']) and (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_READ']) and \
           ((section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_WRITE']) or 
            (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE']) or \
           (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_CNT_INITIALIZED_DATA']))and b'.text' in section.Name.strip(b'\x00').lower():
            
            old_nextPointer = section.PointerToRawData
            text_section = section
            
            print(section.Name.strip(b'\x00'))

            if text_section is None or text_section.SizeOfRawData == 0:
                print("Error: .text section not found")
                return None, None, None, None

            old_rawPointer = text_section.PointerToRawData
            old_size = text_section.Misc
            virtual_address = text_section.VirtualAddress
            image_base = pe.OPTIONAL_HEADER.ImageBase
            section_text = pe_data[text_section.PointerToRawData: text_section.PointerToRawData + text_section.Misc]

            #bitness = 64 if pe.FILE_HEADER.Machine == 0x8664 else 32

            if pe.FILE_HEADER.Machine == 0x8664:
                decoder = Decoder(64, section_text, ip = image_base+virtual_address)
                bit = 64
                address_pattern_short = re.compile(r'\b,?[0-9A-Fa-f]{12}h\b|,?\[\b[0-9A-Fa-f]{12}h\b\]')

            else:
                decoder = Decoder(32, section_text, ip = image_base+virtual_address)
                bit = 32
                address_pattern_short = re.compile(r'\b,?[0-9A-Fa-f]{6}h\b|,?\[\b[0-9A-Fa-f]{6}h\b\]')

            print(bit)

            info_factory = InstructionInfoFactory()
            formatter = Formatter(FormatterSyntax.NASM)

            new_text = b''

            text_start = text_section.VirtualAddress + image_base
            text_end = text_start + text_section.Misc_VirtualSize

            jump_mappings = {
            '70': '0F80',  # JO -> JNO
            '71': '0F81',  # JNO -> JNO
            '72': '0F82',  # JB/JNAE -> JB/JNAE
            '73': '0F83',  # JAE/JNB -> JAE/JNB
            '74': '0F84',  # JE/JZ -> JE/JZ
            '75': '0F85',  # JNE/JNZ -> JNE/JNZ
            '76': '0F86',  # JBE/JNA -> JBE/JNA
            '77': '0F87',  # JA/JNBE -> JA/JNBE
            '78': '0F88',  # JS -> JS
            '79': '0F89',  # JNS -> JNS
            '7A': '0F8A',  # JP/JPE -> JP/JPE
            '7B': '0F8B',  # JNP/JPO -> JNP/JPO
            '7C': '0F8C',  # JL/JNGE -> JL/JNGE
            '7D': '0F8D',  # JGE/JNL -> JGE/JNL
            '7E': '0F8E',  # JLE/JNG -> JLE/JNG
            '7F': '0F8F',  # JG/JNLE -> JG/JNLE
            'EB': 'E9',    # JMP -> JMP
            'E2': '0F85',  # loop
            'E0': '0F8A',  #loopne    
            'E1': '0F82',  #loope   
            'E3': 'E9'  #loope 
            }

            nop_cnt = 0
            increase_instr = 0

            jump_dict={}
            caller_callee_dict={}
            checking_target_address={}
            modified_address={}

            for instr in tqdm(decoder):

                time.sleep(0.0001)

                checker_80 = 0

                disasm = formatter.format(instr)
                op_code = instr.op_code()

                offsets = decoder.get_constant_offsets(instr)      

                present_instr = pe_data[text_section.PointerToRawData + (instr.ip-(image_base+virtual_address)):text_section.PointerToRawData + ((instr.next_ip)-(image_base+virtual_address))]
                present_address = (instr.ip+nop_cnt+increase_instr)

                modified_address[instr.ip] = present_address
                #print(hex(instr.ip),hex(present_address),instr, present_instr.hex(), type(present_instr), instr.ip, present_address, type(instr.ip),code_to_string(instr.code),"|",increase_instr, type(present_instr), disasm)
                if any(x in disasm for x in ('ret', 'int 3', 'nop')):
                    new_text += present_instr
                    continue

                op = disasm.split(' ')[0]

        #         if ('push' in op) or ('pop' in op) or ('test' in op) or ('xor' in op):
        #             new_text += present_instr
        #             new_text += (b'\x90'*number_of_nop)
        #             nop_cnt+=(1*number_of_nop) 
        #             continue 

                prefixes = ''
                ori_present_instr = present_instr
                prefixes, present_instr = is_prefixes(present_instr.hex())

                if 'REL' not in code_to_string(instr.code): # 절대주소
                    value = address_pattern_short.findall(str(instr))

                    if value:
                        value, hex_value = value_int_convert(frozenset(value))

                    else:
                        saperator = [present_instr.hex()[i:i+2] for i in range(0, len(present_instr.hex()), 2)]

                        if 'MOV_RM32_IMM32' in code_to_string(instr.code) and saperator[-1] =='80' and len(present_instr.hex()) == 14:
                            value = present_instr[3:6].hex()
                            hex_value =  to_little_endian(value)
                            value = int(hex_value,16)
                            checker_80 = 1

                        else:
                            value = 0

                    if text_start <= value <= text_end:
                        caller_callee_dict[instr.ip] = value
                        target_address = to_little_endian(hex_value)
                        target_address +='00'
                        op_code = present_instr.hex().replace(target_address.lower(),'')

                        adding_nop_cnt, increace_instruction, increase_address = count_instructions(instr.ip, value, section_text, bit, number_of_nop, dict_to_frozenset(jump_dict), nop_cnt, increase_instr, pe_data, text_section, image_base, virtual_address) 

                        i_cnt = sum(increase_address.values())

                        if instr.ip < value:
                            target_address = value + (nop_cnt + adding_nop_cnt + (increase_instr))+(i_cnt)

                        if instr.ip > value:
                            if (len(increase_address) and (list(increase_address.keys())[0] == instr.ip)):
                                i_cnt = 0

                            target_address = value + (nop_cnt - adding_nop_cnt - (i_cnt)) + increase_instr

                        operand = hex(target_address).replace('x','0',1) # target_address affset

                        if len(operand)>8:
                            operand = operand[1:]

                        if len(operand)<8:
                            operand = '0'+operand

                        operand = to_little_endian(operand)

                        if checker_80 ==1:
                            op_code = present_instr.hex()[:6]
                            new_ins = op_code+operand+'80'
                            new_ins = new_ins.replace('0080','80',1)

                        else: 
                            new_ins = op_code+operand

                        mc_code =  bytes.fromhex((new_ins))
                        new_text+= mc_code

                        checking_target_address[present_address] = target_address

                        if should_add_nop(str(instr)):
                            new_text += (b'\x90'*number_of_nop)
                            nop_cnt+=(1*number_of_nop)
                            continue

                    else:                
                        if prefixes:
                            ins = prefixes+present_instr
                            present_instr = ins

                        new_text += present_instr

                        if should_add_nop(str(instr)):
                           # print("no rel : -->",hex(instr.ip),hex(present_address),instr, present_instr.hex(), type(present_instr), instr.ip, present_address, type(instr.ip),code_to_string(instr.code),"|",increase_instr, type(present_instr), disasm)
                            new_text += (b'\x90'*number_of_nop)
                            nop_cnt+=(1*number_of_nop) 
                            continue           

                if 'REL' in code_to_string(instr.code):
                   
                    op_code = present_instr.hex()[:2]
                    operand = present_instr.hex()[2:]

                    if 'ptr' in str(instr) and len(operand)>8:
                        op_code = present_instr.hex()[:4]
                        operand = present_instr.hex()[4:]

                    ori_operand = operand
                    present_address = (instr.ip+nop_cnt+increase_instr) 

                    address = instr.ip+len(instr)+hex_to_signed_int(to_little_endian(operand))

                    if instr.ip < address:
                        operand = to_little_endian(operand)
                        int_operand = hex_to_signed_int(operand)

                        adding_nop_cnt, increace_instruction, increase_address = count_instructions(instr.ip, address, section_text, bit, number_of_nop, dict_to_frozenset(jump_dict), nop_cnt, increase_instr, pe_data, text_section, image_base, virtual_address) 

                        i_cnt=0
                        i_cnt = sum(increase_address.values())

                        target_address = len(instr) + present_address + (int_operand + adding_nop_cnt + (i_cnt))
                        offset = target_address - present_address - len(instr)

                        operand = hex(offset).replace('x','0',1)       
                        operand = operand.replace('00','',1)

                        if len(operand)%2 !=0:
                            new_operand = '0'+operand
                            operand = new_operand

                        operand = to_little_endian(operand)

                        if len(operand) != 8:
                            operand += '0' * (8-len(operand))

                        if offset<0:
                            operand = minus_offset(offset, ori_operand)

                        new_ins = op_code+operand

                        if prefixes:
                            new_ins = prefixes.hex()+op_code+operand


                        if len(present_instr.hex()) != len(new_ins):
                            if ('short' in str(instr)) or ('loop' in str(instr)) or ('jecxz' in str(instr)):
                                ori_operand = present_instr.hex()[2:]
                                operand = to_little_endian(ori_operand)
                                int_operand = hex_to_signed_int(operand)

                                i_cnt = 0
                                i_cnt = sum(increase_address.values())

                                target_address = len(instr) + present_address + (int_operand + adding_nop_cnt + (i_cnt))

                                offset = target_address - present_address - len(instr)

                                operand = hex(offset).replace('x','0',1)

                                if len(operand)%2 !=0:
                                    operand = operand.replace('0','',1)

                                int_operand = int(operand,16)

                                if int_operand>=127:
                                    op_code = present_instr.hex()[:2]
                                    operand = present_instr.hex()[2:]
                                    op_code = jump_mappings[op_code.upper()]

                                    new_ins_len = 6

                                    if 'E9' in op_code:
                                        new_ins_len = 5

                                    if 'E2' in op_code:
                                        preprocessing_code = '4883C9FF' # dec cex
                                        op_code = preprocessing_code+op_code
                                        new_ins_len = 10

                                    if 'E3' in op_code:
                                        new_ins_len = 2+6+5
                                        preprocessing_code = '85C9' # dec cex
                                        jnz_inst = '0F85'+ make_new_increase_instruction_operand(target_address - present_address - new_ins_len-1)
                                        op_code = preprocessing_code+jnz_inst+op_code

                                    int_operand = target_address - present_address - new_ins_len

                                    operand = make_new_increase_instruction_operand(int_operand)

                                    increase_instr += new_ins_len - len(instr)
                                    jump_dict[instr.ip] = int(new_ins_len - len(instr))

                                else: 
                                    if offset<0:
                                        operand = minus_offset(offset,ori_operand)

                                    else:
                                        while 1:
                                            if len(ori_operand) == len(operand):
                                                break
                                            else:
                                                operand = operand.replace('0','',1)

                            new_ins = op_code+operand

                        mc_code =  bytes.fromhex((new_ins))

                        new_text += mc_code  
                        checking_target_address[present_address] = target_address
                        caller_callee_dict[instr.ip] = address  

                        if should_add_nop(str(instr)):
                            #print("   ->",(hex(instr.ip),hex(present_address),instr, present_instr.hex(), type(present_instr), instr.ip, present_address, type(instr.ip),code_to_string(instr.code),"|",increase_instr, type(present_instr), disasm))
                            new_text += (b'\x90'*number_of_nop)
                            nop_cnt+=(1*number_of_nop)
                            continue


                    elif instr.ip > address:
                        #print("    위로 뛸꺼고")

                        address = instr.ip+len(instr)+hex_to_signed_int(to_little_endian(operand))

                        operand = to_little_endian(operand)
                        int_operand = hex_to_signed_int(operand)

                        adding_nop_cnt, increace_instruction, increase_address = count_instructions(instr.ip, address, section_text, bit, number_of_nop, dict_to_frozenset(jump_dict), nop_cnt, increase_instr, pe_data, text_section, image_base, virtual_address) 

                        present_address = (instr.ip  + nop_cnt + increase_instr)

                        i_cnt = 0     
                        i_cnt = sum(increase_address.values())

                        if (len(increase_address) and (list(increase_address.keys())[0] == instr.ip)):
                            i_cnt = 0

                        target_address = len(instr) + present_address + (int_operand - adding_nop_cnt - (i_cnt))

                        offset = target_address - present_address - len(instr) 
                        operand = negative_to_little_endian_hex(offset)

                        new_ins = op_code+operand

                        if prefixes:
                            new_ins = prefixes.hex()+op_code+operand

                        if len(present_instr.hex()) != len(new_ins):
                            if 'ff' in new_ins:
                                operand = operand.replace('ff','',)
                                new_ins = op_code+operand

                            if ('short' in str(instr)) or ('loop' in str(instr)) or ('jecxz' in str(instr)):
                                i_cnt = 0                               
                                i_cnt = sum(increase_address[i] for i in list(increase_address.keys()) if address <= i < instr.ip)

                                target_address = len(instr) + present_address + (int_operand - adding_nop_cnt - (i_cnt))

                                int_operand = target_address - present_address - len(instr)
                                operand = negative_to_little_endian_hex(int_operand)      
                                operand = operand.replace('ff','')

                                if int_operand<=(-128): 
                                    op_code = present_instr.hex()[:2]
                                    operand = present_instr.hex()[2:]
                                    op_code = jump_mappings[op_code.upper()]

                                    new_ins_len = 6

                                    if 'E9' in op_code:
                                        new_ins_len = 5

                                    if 'E2' in op_code:
                                        preprocessing_code = '4883C9FF' # dec ecx
                                        op_code = preprocessing_code+op_code
                                        new_ins_len = 10

                                    if 'E3' in op_code:
                                        new_ins_len = 2+6+5
                                        preprocessing_code = '85C9' # dec cex
                                        jnz_operand = negative_to_little_endian_hex(target_address - present_address - new_ins_len -1)
                                        jnz_operand = jnz_operand + '0' * (8-len(jnz_operand))
                                        jnz_inst = '0F85'+ jnz_operand
                                        op_code = preprocessing_code+jnz_inst+op_code

                                    int_operand = target_address - present_address - new_ins_len
                                    new_operand = negative_to_little_endian_hex(int_operand)

                                    operand = new_operand + '0' * (8-len(new_operand))

                                    increase_instr += new_ins_len - len(instr)
                                    jump_dict[instr.ip] = new_ins_len - len(instr)

                                new_ins = op_code+operand   

                        mc_code =  bytes.fromhex((new_ins))
                        new_text += mc_code

                        checking_target_address[present_address] = target_address
                        caller_callee_dict[instr.ip] = address

                        if should_add_nop(str(instr)):
                            new_text += (b'\x90'*number_of_nop)
                            nop_cnt+=(1*number_of_nop)
                            continue
                            
            new_text_list.append(new_text)
    return new_text_list, modified_address , caller_callee_dict, checking_target_address

def calc_offset(target_address, address, ori_operand, op_code, size):
    
    if address > target_address:
        print(" up jump")
        new_operand = address - target_address - size #len(instr)
        operand = negative_to_little_endian_hex(new_operand)

    if address < target_address:
        print(" down jump")
        new_operand = target_address - address - size #len(instr)
        operand = hex(new_operand).replace('x','0',1) # target_address affset
        operand = operand.replace('00','',1)


        if len(ori_operand) - len(operand) != 0:
            new_operand = '0'* int(len(ori_operand) - len(operand))
            new_operand+= operand
            operand = new_operand

        operand = to_little_endian(operand)
        
    new_ins = op_code+operand
          
    return new_ins, op_code, operand 

def unmatched_address_chacker(modified_address, caller_callee_dict, checking_target_address):
    new_address_to_ori_address = {v: k for k, v in modified_address.items()}
    modifying_address = {}

    for caller, callee in checking_target_address.items():
        try:
            if caller in new_address_to_ori_address and callee in new_address_to_ori_address:
                ori_caller = new_address_to_ori_address[caller]
                ori_callee = new_address_to_ori_address[callee]

                if caller_callee_dict[ori_caller] != ori_callee:
                    modifying_address[caller] = modified_address[caller_callee_dict[ori_caller]]
                    continue
            else:
                if caller in new_address_to_ori_address:
                    ori_caller = new_address_to_ori_address[caller]
                    ori_callee = caller_callee_dict[ori_caller]
                    new_callee = modified_address[ori_callee]
                    modifying_address[caller] = new_callee
                    continue

                if callee in new_address_to_ori_address:
                    ori_callee = new_address_to_ori_address[callee]
                    ori_caller = caller_callee_dict[ori_callee]
                    new_caller = modified_address[ori_caller]
                    modifying_address[new_caller] = callee
                    continue
        except KeyError:
            continue

    return modifying_address

def modify_instruction_at_address(binary_data, text_section, target_address, new_ins):
    relative_address = target_address - text_section.VirtualAddress
    binary_data = bytearray(binary_data)
    binary_data[text_section.PointerToRawData + relative_address:text_section.PointerToRawData + relative_address + len(new_ins)] = bytes.fromhex((new_ins))
    return binary_data

def is_direct_address(target, decoded_instructions):
    immediate_pattern = re.compile(r'\b0x[0-9A-Fa-f]+\b')
    for (offset, size, instruction, hexdump) in decoded_instructions:
        if offset == target:
            if bool(immediate_pattern.search(instruction)) and ('ff' not in hexdump):
                return "ABS", offset, instruction, hexdump, size
            else:
                return "REL", offset, instruction, hexdump, size
            
@lru_cache(maxsize=128)            
def decode_instructions(binary_data, start_address, bitness):
    if bitness == 64:
        mode = distorm3.Decode64Bits
    elif bitness == 32:
        mode = distorm3.Decode32Bits
    else:
        raise ValueError("Unsupported bitness. Only 32 and 64 are supported.")
    
    decoded_instructions = distorm3.Decode(start_address, binary_data, mode)
    return decoded_instructions

def valid_address_check(file_path, save_dir, caller_callee_dict, checking_target_address, modified_address, number_of_nop):

    modifying_address = unmatched_address_chacker(modified_address, caller_callee_dict, checking_target_address)
    print("valid_address_check:", modifying_address, len(modifying_address))
    
    if not modifying_address:
        return
    
    pe = pefile.PE(save_dir)
    pe_data = open(save_dir, "rb").read()

    binary_data_list = []
    for section in pe.sections:
        if b'.text' in section.Name.strip(b'\x00'):
            text_section = section

            if text_section is None or text_section.SizeOfRawData == 0:
                print("Error: .text section not found")
                return

            image_base = pe.OPTIONAL_HEADER.ImageBase

            text_start = text_section.VirtualAddress + image_base
            text_end = text_start + text_section.Misc_VirtualSize

            binary_data = text_section.get_data()

            if pe.FILE_HEADER.Machine == 0x8664:
                bitness = 64
            else:
                bitness = 32

            decoded_instructions = decode_instructions(binary_data, text_start, bitness)

            for target, destination in modifying_address.items():
                try:
                    address_type, address, instruction, hexdump, size = is_direct_address(target, decoded_instructions)

                    instr_str = str(instruction)
                    present_instr = hexdump

                    prefixes = None
                    prefixes, present_instr = is_prefixes(present_instr.upper())

                    if 'REL' not in address_type:
                        value = address_pattern_short.findall(instr_str)

                        if not value:
                            value = address_pattern_long.findall(instr_str)

                        if value:
                            value, hex_value = value_int_convert(value)

                        else:
                            value = 0

                        if text_start <= value <= text_end:
                            caller_callee_dict[target] = value
                            target_address = to_little_endian(hex_value) + '00'
                            op_code = present_instr[:2]

                            operand = hex(destination).replace('x', '0', 1)
                            operand = to_little_endian(operand)

                            new_ins = op_code.hex() + operand

                    elif 'REL' in address_type:
                        op_code = present_instr[:2]
                        operand = present_instr[2:]
                        ori_operand = operand

                        if len(operand) > 8:
                            op_code = present_instr[:4]
                            operand = present_instr[4:]
                            ori_operand = operand

                        value = address_pattern_short.findall(instr_str)

                        if value:
                            new_ins, op_code, operand = calc_offset(destination, address, ori_operand, op_code, size)

                        else:
                            value = address_pattern_long.findall(instr_str)
                            if value:
                                new_ins, op_code, operand = calc_offset(destination, address, ori_operand, op_code, size)

                    binary_data = modify_instruction_at_address(binary_data, text_section, target, new_ins)
                except:
                    pass
                
            binary_data_list.append(binary_data)
        
    new_text = modify_headers(file_path, binary_data_list, fin=1)
    save_dir = modify_section(file_path, new_text, save_dir, str(number_of_nop), fin=1)
    modify_tramp(save_dir, modified_address, fin=1)
    modify_rdata(save_dir, modified_address, fin=1)

#------------------------------------Single processing version main function--------------------------------------------------------   
# if __name__ == '__main__':
        
# #     sample_dir = '../sample/section_move_sample/'
# #     save_dir = '../sample/perturbated_sample/adding_nop/'

#     sample_dir = '../sample/section_move_benign_sample/'
#     #save_dir = '../sample/perturbated_sample/adding_nop/'
#     save_dir = sample_dir
    
            
# #     sample_dir = '../evaluation/section_move_sample/'
# #     save_dir = '../evaluation/perturbated_sample/adding_nop/'
    
#     samples = list_files_by_size(sample_dir)
#     create_directory(save_dir)
    
#     number_of_nop = 1
    
#     for sample in samples:
#         #save_dir = '../sample/perturbated_sample/adding_nop/'
#         save_dir = sample_dir
#         #save_dir = '../evaluation/perturbated_sample/adding_nop/'
#         if '.ipynb' in sample or '.pickle' in sample or '.txt' in sample or '.zip' in sample:
#             continue

# #         if '085c1a53091bf9c9ff15844c848200b119e74d11298f3caa57e285619bb4fa28.exe' not in sample:
# #         if '0c34ed46c75b33e392091d8fb7b4449b2fd78b6a56ae7d89f5e6441c48f10692_new.exe' in sample or 'PEview_new.exe' in sample or 'hello_32_new.exe' in sample or 'Frombook_new.exe' in sample:
#         if 'PEview_new.exe' not in sample:
#             continue

#         file_path = sample_dir+sample

#         print(file_path)
#         try:  
#             new_text, modified_address, caller_callee_dict, checking_target_address = make_new_text(file_path, number_of_nop)
            
#             if new_text is None:
#                 print(f"[+] Error : failed to make new_text section.") 
                
#             else:
#                 print("modified text sections : ",len(new_text))
#                 #print(new_text[0], '\n',new_text[1])
#                 new_text = modify_headers(file_path, new_text)
#                 save_dir = modify_section(file_path, new_text, save_dir, number_of_nop)
#                 modify_tramp(save_dir, modified_address)
#                 save_dir = modify_rdata(save_dir, modified_address)
#                 valid_address_check(file_path, save_dir, caller_callee_dict, checking_target_address, modified_address, str(number_of_nop))
#                 print("Done!!",sample)
                
#         except pefile.PEFormatError:
#             continue 


#------------------------------------multi processing version main function--------------------------------------------------------
# def process_sample(sample):
#     sample_dir = '../evaluation/section_move_sample/'
#     save_dir = '../evaluation/perturbated_sample/adding_nop_100/'
    
#     file_path = sample_dir + sample
    
#     number_of_nop = 100
    
#     try:
#         new_text, modified_address, caller_callee_dict, checking_target_address = make_new_text(file_path, number_of_nop)

#         if new_text is None:
#             print(f"[+] Error: failed to make new_text section for {sample}.") 
#             return

#         new_text = modify_headers(file_path, new_text)
#         save_dir = modify_section(file_path, new_text, save_dir, number_of_nop)
#         modify_tramp(save_dir, modified_address)
#         save_dir = modify_rdata(save_dir, modified_address)
#         valid_address_check(file_path, save_dir, caller_callee_dict, checking_target_address, modified_address, str(number_of_nop))
#         print(f"Done processing {sample}")
        
#     except pefile.PEFormatError:
#         print(f"[+] PEFormatError: {sample}")
#         return

# def main():
#     sample_dir = '../evaluation/section_move_sample/'
#     save_dir = '../evaluation/perturbated_sample/adding_nop/'
    
#     samples = list_files_by_size(sample_dir)
#     create_directory(save_dir)

#     # 필터링을 추가하여 유효한 샘플만 처리하도록 합니다.
#     samples = [sample for sample in samples if not any(ext in sample for ext in ['.ipynb', '.pickle', '.txt', '.zip'])]

#     # 멀티프로세싱을 위해 Pool 생성
#     num_processes = max(1, multiprocessing.cpu_count() // 2)  # 최소 1개의 프로세스를 사용하도록 설정
#     with multiprocessing.Pool(processes=num_processes) as pool:
#         pool.map(process_sample, samples)

# if __name__ == '__main__':
#     main()
#------------------------------------multi processing version main function--------------------------------------------------------

#------------------------------------Dynamic Task Assignment with Job Queue multi processing version main function--------------------------------------------------------

# def process_sample(sample):
#     sample_dir = '../evaluation/section_move_sample/'
#     save_dir = '../evaluation/perturbated_sample/adding_nop_100/'
    
#     file_path = sample_dir + sample
    
#     number_of_nop = 100
    
#     try:
#         new_text, modified_address, caller_callee_dict, checking_target_address = make_new_text(file_path, number_of_nop)

#         if new_text is None:
#             print(f"[+] Error: failed to make new_text section for {sample}.") 
#             return

#         new_text = modify_headers(file_path, new_text)
#         save_dir = modify_section(file_path, new_text, save_dir, number_of_nop)
#         modify_tramp(save_dir, modified_address)
#         save_dir = modify_rdata(save_dir, modified_address)
#         valid_address_check(file_path, save_dir, caller_callee_dict, checking_target_address, modified_address, str(number_of_nop))
#         print(f"Done processing {sample}")
        
#     except pefile.PEFormatError:
#         print(f"[+] PEFormatError: {sample}")
#         return
    
    
# def worker(input_queue):
#     while True:
#         sample = input_queue.get()
#         if sample is None:
#             break
#         process_sample(sample)
#         input_queue.task_done()

# def main():
#     sample_dir = '../evaluation/section_move_sample/'
#     save_dir = '../evaluation/perturbated_sample/adding_nop_100/'
    
#     samples = list_files_by_size(sample_dir)
#     create_directory(save_dir)

#     # 유효한 샘플만 필터링
#     samples = [sample for sample in samples if not any(ext in sample for ext in ['.ipynb', '.pickle', '.txt', '.zip'])]

#     # 작업 큐 생성
#     input_queue = multiprocessing.JoinableQueue()

#     # CPU 코어 수의 절반만 사용하도록 설정
#     num_processes = max(1, multiprocessing.cpu_count() // 10)

#     # 워커 프로세스 생성 및 시작
#     processes = []
#     for _ in range(num_processes):
#         p = multiprocessing.Process(target=worker, args=(input_queue,))
#         p.start()
#         processes.append(p)

#     # 작업 큐에 작업 추가
#     for sample in samples:
#         input_queue.put(sample)

#     # 모든 작업이 완료되면 None을 넣어 워커 프로세스를 종료시킴
#     input_queue.join()
#     for _ in range(num_processes):
#         input_queue.put(None)

#     # 워커 프로세스 종료
#     for p in processes:
#         p.join()

#     print("All tasks are completed.")

# if __name__ == '__main__':
#     main()

#----------------------------------------------------------------------
# def process_sample(sample):
#     #sample_dir = '../evaluation/section_move_sample/'
#     #save_dir = '../evaluation/perturbated_sample/adding_nop_100/'
    
#     sample_dir = '../evaluation//clamav/resource_change_involve_data/'
#     save_dir = '../evaluation/clamav/resource_change+adding_nop_100/'
    
#     file_path = sample_dir + sample
    
#     number_of_nop = 100
    
#     try:
#         new_text, modified_address, caller_callee_dict, checking_target_address = make_new_text(file_path, number_of_nop)

#         if new_text is None:
#             print(f"[+] Error: failed to make new_text section for {sample}.") 
#             return

#         new_text = modify_headers(file_path, new_text)
#         save_dir = modify_section(file_path, new_text, save_dir, number_of_nop)
#         modify_tramp(save_dir, modified_address)
#         save_dir = modify_rdata(save_dir, modified_address)
#         valid_address_check(file_path, save_dir, caller_callee_dict, checking_target_address, modified_address, str(number_of_nop))
#         print(f"Done processing {sample}")
        
#     except pefile.PEFormatError:
#         print(f"[+] PEFormatError: {sample}")
#         return
    
    
# def worker(input_queue):
#     while True:
#         sample = input_queue.get()
#         if sample is None:
#             break
#         process_sample(sample)
#         input_queue.task_done()

# def main():
#     sample_dir = '../evaluation//clamav/resource_change_involve_data/'
#     save_dir = '../evaluation/clamav/resource_change+adding_nop_100/'
    
#     samples = list_files_by_size(sample_dir)
#     create_directory(save_dir)

#     # 유효한 샘플만 필터링
#     samples = [sample for sample in samples if not any(ext in sample for ext in ['.ipynb', '.pickle', '.txt', '.zip'])]

#     # 작업 큐 생성
#     input_queue = multiprocessing.JoinableQueue()

#     # CPU 코어 수의 절반만 사용하도록 설정
#     num_processes = max(1, multiprocessing.cpu_count() // 10)

#     # 워커 프로세스 생성 및 시작
#     processes = []
#     for _ in range(num_processes):
#         p = multiprocessing.Process(target=worker, args=(input_queue,))
#         p.start()
#         processes.append(p)

#     # 작업 큐에 작업 추가
#     for sample in samples:
#         input_queue.put(sample)

#     # 모든 작업이 완료되면 None을 넣어 워커 프로세스를 종료시킴
#     input_queue.join()
#     for _ in range(num_processes):
#         input_queue.put(None)

#     # 워커 프로세스 종료
#     for p in processes:
#         p.join()

#     print("All tasks are completed.")

# if __name__ == '__main__':
#     main()

#------------------------------------------------------------------------------------
# def process_sample(sample):
#     #sample_dir = '../evaluation/section_move_sample/'
#     #save_dir = '../evaluation/perturbated_sample/adding_nop_100/'
    
#     sample_dir = '../evaluation//clamav/resource_change_involve_data/'
#     save_dir = '../evaluation/clamav/resource_change+adding_nop_100/'
    
#     file_path = sample_dir + sample
    
#     number_of_nop = 100
    
#     try:
#         new_text, modified_address, caller_callee_dict, checking_target_address = make_new_text(file_path, number_of_nop)

#         if new_text is None:
#             print(f"[+] Error: failed to make new_text section for {sample}.") 
#             return

#         new_text = modify_headers(file_path, new_text)
#         save_dir = modify_section(file_path, new_text, save_dir, number_of_nop)
#         modify_tramp(save_dir, modified_address)
#         save_dir = modify_rdata(save_dir, modified_address)
#         valid_address_check(file_path, save_dir, caller_callee_dict, checking_target_address, modified_address, str(number_of_nop))
#         print(f"Done processing {sample}")
        
#     except pefile.PEFormatError:
#         print(f"[+] PEFormatError: {sample}")
#         return
    
    
# def worker(input_queue):
#     while True:
#         sample = input_queue.get()
#         if sample is None:
#             break
#         process_sample(sample)
#         input_queue.task_done()

# def main():
#     sample_dir = '../evaluation//clamav/resource_change_involve_data/'
#     save_dir = '../evaluation/clamav/resource_change+adding_nop_100/'
    
#     samples = list_files_by_size(sample_dir)
#     create_directory(save_dir)

#     # 유효한 샘플만 필터링
#     samples = [sample for sample in samples if not any(ext in sample for ext in ['.ipynb', '.pickle', '.txt', '.zip'])]

#     # 작업 큐 생성
#     input_queue = multiprocessing.JoinableQueue()

#     # CPU 코어 수의 절반만 사용하도록 설정
#     num_processes = max(1, multiprocessing.cpu_count() // 10)

#     # 워커 프로세스 생성 및 시작
#     processes = []
#     for _ in range(num_processes):
#         p = multiprocessing.Process(target=worker, args=(input_queue,))
#         p.start()
#         processes.append(p)

#     # 작업 큐에 작업 추가
#     for sample in samples:
#         input_queue.put(sample)

#     # 모든 작업이 완료되면 None을 넣어 워커 프로세스를 종료시킴
#     input_queue.join()
#     for _ in range(num_processes):
#         input_queue.put(None)

#     # 워커 프로세스 종료
#     for p in processes:
#         p.join()

#     print("All tasks are completed.")

# if __name__ == '__main__':
#     main()

#--------------------------------------------labeling_sample_multi_processing------------------------------------------
def process_sample(sample, root, save_dir, number_of_nop):
    file_path = os.path.join(root, sample)
    output_filename_1 = sample.replace('.exe', '_adding_'+str(number_of_nop)+'.exe')
    output_filename_2 = sample.replace('.exe', '_nop_fin_'+str(number_of_nop)+'.exe')
    output_filepath_1 = os.path.join(save_dir, output_filename_1)
    output_filepath_2 = os.path.join(save_dir, output_filename_2)

    # 두 가지 파일 중 하나라도 존재하면 작업을 건너뜀
    if os.path.isfile(output_filepath_1) or os.path.isfile(output_filepath_2):
        return

    try:
        new_text, modified_address, caller_callee_dict, checking_target_address = make_new_text(file_path, number_of_nop)

        if new_text is None:
            print(f"[+] Error: Failed to create new_text section for {sample}.")
        else:
            print("len_new_text:", len(new_text))
            new_text = modify_headers(file_path, new_text)
            save_dir = modify_section(file_path, new_text, save_dir, number_of_nop)
            print(len(modified_address))
            modify_tramp(save_dir, modified_address)
            save_dir = modify_rdata(save_dir, modified_address)
            valid_address_check(file_path, save_dir, caller_callee_dict, checking_target_address, modified_address, str(number_of_nop))
            print("Done!!", sample)
    except pefile.PEFormatError:
        pass

def worker(input_queue):
    while True:
        task = input_queue.get()
        if task is None:
            break
        sample, root, save_dir, number_of_nop = task
        process_sample(sample, root, save_dir, number_of_nop)
        input_queue.task_done()

def main():
    sample_dir = '../sample/perturbated_labling_sample/section_move/'
    save_dir_base = '../sample/perturbated_labling_sample/adding_nop/'
    
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
        if 'ok' in root.split(os.sep):  # 'OK' 디렉토리를 건너뛰기
            continue
            
        if len(files) <= 10:  # 파일이 10개 이하인 디렉토리는 건너뛰기
            continue
        
        save_dir = os.path.join(save_dir_base, os.path.basename(root))
        create_directory(save_dir+'/')
        
        for sample in list_files_by_size(root):
            if any(ext in sample for ext in ['.ipynb', '.pickle', '.txt', '.zip']) or '.' not in sample:
                continue

            # 작업 큐에 작업 추가
            input_queue.put((sample, root, save_dir+'/', 1))

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

