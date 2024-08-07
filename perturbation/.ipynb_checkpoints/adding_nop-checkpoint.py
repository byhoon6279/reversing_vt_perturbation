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
from common_function import *

old_rawPointer = 0
old_nextPointer = 0

def modify_section(file_path, new_text, save_dir, number_of_nop, fin = None):
    global old_rawPointer
    global old_nextPointer
    number_of_nop = str(number_of_nop)
    file_format = '.'+file_path.split('.')[-1]
    
    pe = pefile.PE(file_path)
        
    for section in pe.sections:
        #if section.Name.strip(b'\x00').lower() == b'.text' or section.Name.strip(b'\x00').upper() == b'CODE':
        if section.Name.decode().strip('\x00').lower() in ['.text', 'text', 'code', '.code']:
            text_section = section
            break
    
    tmp_file = file_path.replace(file_format, "_tmp"+file_format)
    
    with open(tmp_file, "rb") as tmp:
        tmp_binary = tmp.read()

    new_binary = tmp_binary[:old_rawPointer]
    new_binary += new_text
    new_binary += tmp_binary[text_section.PointerToRawData+text_section.SizeOfRawData:]

    with open(file_path.replace(file_format, "_adding_"+number_of_nop+file_format), "wb") as f: 
        f.write(new_binary)
        
    os.remove(tmp_file)
    
    file_name = file_path.split('/')[-1].replace(file_format, "_adding_"+number_of_nop+file_format)
    
    if fin:
        print(f"[+] new size of binary : {len(new_binary)}")
        file_name = file_name.replace('_adding_'+number_of_nop+file_format,'_nop_fin_'+number_of_nop+file_format)
        
        directory, old_filename = os.path.split(save_dir)
        new_path = os.path.join(directory, file_name)
        
        os.rename(file_path.replace(file_format, "_adding_"+number_of_nop+file_format), new_path)
        #os.system('rm -rf ./'+save_dir)
        print("modified_section_return save_dir : ",new_path)
        return new_path

    else:

        os.rename(file_path.replace(file_format, "_adding_"+number_of_nop+file_format), save_dir+file_name)
        print("modified_section_return save_dir : ",save_dir+file_name)
        return save_dir+file_name

def modify_tramp(save_dir,modified_address, fin = None):
    file_path = save_dir
    pe = pefile.PE(file_path)
    pe_data = open(file_path, "rb").read()

    # .tramp 섹션 찾기
    section = next(section for section in pe.sections if section.Name.rstrip(b'\x00') == b'.Tram')

    virtual_address = section.VirtualAddress
    image_base = pe.OPTIONAL_HEADER.ImageBase
    
    section_start = section.PointerToRawData
    section_size = section.SizeOfRawData
    
    data = bytearray(pe.get_memory_mapped_image()[section_start:section_start + section_size])

    old_value = None
    new_value = None

    for i in range(0, len(data)):
        if '0x90' not in str(hex(data[i])):

            old_value = data[i:i+5]
            index = data.find(data[i:i+5])
            instruction =  data[i:i+5].hex()
            
            present_address = hex(image_base+virtual_address+i)
            instruction_len = int(len(data[i:i+5].hex())/2)
            
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

    # 변경된 데이터를 PE 파일에 반영
    pe.set_bytes_at_offset(section_start + index, new_value)

    output_file_path = file_path 
    pe.write(output_file_path)
    #print(f"Modified PE file saved as {output_file_path}")
    
def modify_rdata(save_dir, modified_address, fin = None):
    # PE 파일 로드
    file_path = save_dir
    pe = pefile.PE(file_path)
    valid_section_names = ['.text', 'text', 'code', '.code']

    # .rdata 섹션 찾기
    for section in pe.sections:
        if section.Name.decode().strip('\x00').lower() in ['.data', '.rdata', 'data', 'const', 'rdata']: # add malware's custom section name if you want
            section = section
            rdata_start = section.VirtualAddress
            rdata_end = rdata_start + section.Misc_VirtualSize
            section_size = section.SizeOfRawData
            section_start = section.PointerToRawData

            data = bytearray(pe.get_memory_mapped_image()[rdata_start:rdata_start + section_size])
            #print(data)

            # 절대 주소 필터링을 위한 범위 설정
            image_base = pe.OPTIONAL_HEADER.ImageBase
            #text_section = next(section for section in pe.sections if section.Name.rstrip(b'\x00').lower() == b'.text' or section.Name.strip(b'\x00').upper() == b'CODE')
            text_section = next(section for section in pe.sections if any(section.Name.decode().strip('\x00').lower() == name for name in valid_section_names))
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
    

def find_prologue_epilogue(txt_dir):
    addr_dict = {}

    with open(txt_dir, "r") as f:
        data = f.readlines()

    for line in data:
        if 'Prologue : ' in line or 'Epilogue : ' in line:
            if 'Not found' in line:
                continue
            addr_dict[line.split(':')[1].strip()] = line.split(':')[0].strip()

    #print('rm -rf ./'+txt_dir)
    #os.system('rm -rf ./'+txt_dir)
    
    return addr_dict

def to_little_endian(hex_str):
    # 2자리씩 끊어서 리스트로 만듭니다.
    bytes_list = [hex_str[i:i+2] for i in range(0, len(hex_str), 2)]
    # 리스트를 역순으로 뒤집습니다.
    bytes_list.reverse()
    # 다시 문자열로 결합합니다.
    little_endian_str = ''.join(bytes_list)
    return little_endian_str
    
    
def should_add_nop(instruction):
    control_flow_instructions = [
        # 분기 명령어
        'jmp', 'jz', 'je', 'jnz', 'jne', 'ja', 'jnbe', 'jb', 'jnae', 'jc', 'jae', 'jnb', 'jnc',
        'jbe', 'jna', 'jg', 'jnle', 'jl', 'jnge', 'jge', 'jnl', 'jle', 'jng', 'jo', 'jno', 'js', 'jns',
        # 호출 및 리턴 명령어
        'call', 'ret', 'retf', 'iret', 'iretd', 'iretq',
        # 인터럽트 명령어
        'int', 'int3', 'into',
        # 제어 흐름 변경 명령어
        'loop', 'loope', 'loopne', 'syscall', 'sysret'
    ]

    opcode = instruction.split()[0].lower()
    return opcode not in control_flow_instructions

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

def hex_to_signed_int(hex_str):
    value = int(hex_str, 16)
    if value & (1 << (len(hex_str) * 4 - 1)):
        value -= 1 << (len(hex_str) * 4)
    return value

def count_instructions(first_address, second_address, section_data, bit, addr, number_of_nop, jump_dict, nop_cnt, increase_instr, address_pattern_long):
    decoder = Decoder(bit, section_data, ip=addr)
    
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
            #try:
            #if hex(instr.ip) in address_dict:
            if instr.ip == end_address:
                    break
                    #continue
#                 if address_dict[hex(instr.ip)]: #프롤로그 에필로그 체크
#                     if instr.ip == end_address:
#                         break
#                     continue

#             except:
            else:
                if ('ret' in str(instr)) or ('int 3' in str(instr)) or ('nop' in str(instr)):
                    continue

                if not should_add_nop(str(instr)):
                    if len(instr)==2:
                        #address = re.findall(r'\b,?[0-9A-Fa-f]{8}h\b|,?\[\b[0-9A-Fa-f]{8}h\b\]', str(instr))
                        address = address_pattern_long.findall(str(instr))

                        if address:
#                             print("  ",hex(instr.ip), instr)
                            address = address[0].replace('00','',1).replace('h','')

                            anc = count_instructions_between_addresses(instr.ip, int(address,16), section_data, bit, addr, number_of_nop)
            
                            total_increase = calculate_instruction_length_increase(instr.ip, int(address,16), section_data, bit, addr, jump_dict, increase_address, address_pattern_long, number_of_nop)

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


def count_instructions_between_addresses(first_address, second_address, section_data, bit, addr, number_of_nop):
    decoder = Decoder(bit, section_data, ip=addr)
         
    instruction_count_num = 0
    jump_counter = {}
    
    start_address = min(first_address, second_address)
    end_address = max(first_address, second_address)

    for instr in decoder:
        
        if (instr.ip < start_address):
            continue
            
        if start_address <= instr.ip <= end_address:
            #try:
            #if hex(instr.ip) in address_dict:
            if instr.ip == end_address:
                break
#                 continue
#                 if address_dict[hex(instr.ip)]: #프롤로그 에필로그 체크
#                     if instr.ip == end_address:
#                         break
#                     continue

#             except:
            else:
                if ('ret' in str(instr)) or ('int 3' in str(instr)) or ('nop' in str(instr)):
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
                continue
    
    return instruction_count_num

def calculate_instruction_length_increase(first_address, second_address, section_data, bit, addr, jump_dict, increase_address, address_pattern_long, number_of_nop):
    decoder = Decoder(bit, section_data, ip=addr)
        
    total_increase = 0
    
    start_address = min(first_address, second_address)
    end_address = max(first_address, second_address)

    for instr in decoder:
        
        if (instr.ip < start_address):
            continue
            
        #else:
        if start_address <= instr.ip <= end_address:
#             try:
            #if hex(instr.ip) in address_dict:
            if instr.ip == end_address:
                break
            #continue
#                 if address_dict[hex(instr.ip)]: #프롤로그 에필로그 체크
#                     if instr.ip == end_address:
#                         break
#                     continue

#             except:
            else:
                if ('ret' in str(instr)) or ('int 3' in str(instr)) or ('nop' in str(instr)):
                    continue

                if not should_add_nop(str(instr)):
                    if len(instr)==2:
                        #address = re.findall(r'\b,?[0-9A-Fa-f]{8}h\b|,?\[\b[0-9A-Fa-f]{8}h\b\]', str(instr))
                        address = address_pattern_long.findall(str(instr))

                        if address:
                            address = address[0].replace('00','',1).replace('h','')

                            offset = int(address,16) - instr.ip - len(instr)
                            
                            anc = count_instructions_between_addresses(instr.ip, int(address,16), section_data, bit, addr, number_of_nop)
                            
                            if number_of_nop ==1:
                                jmp_calibration = 0
                                calibration = 0
                            else:
                                jmp_calibration = sum(value for i, value in increase_address.items() if instr.ip <= i <= int(address,16))
                                calibration = sum(value for i, value in jump_dict.items() if start_address <= i <= end_address)
                            
                            #jump_dict에 아직 저장되지 않은 주소값인 경우 (향후 늘어나는 점프에 대해) 어떻게 대응할것인가? 아래 주석해놓은 거는 nop 5일떄는 실행이 됨, 다만 nop 이 많아질수록 부정확하기떄문에 실행이 안됨
                            
                            operand = offset+anc+calibration+jmp_calibration
                            
                            #if instr.ip == int('4298709') or instr.ip == int('4298733'):
                                #print("     ",hex(instr.ip), instr, operand, offset, anc, calibration, jmp_calibration) # 아마 여기서 D5가 반영이 안되어서 그런걱 같은데, 이걸 어케하냐??
                            
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

def value_int_convert(value):
    value = value[0].replace('h','',1)
    value = value.replace(',','',1)
    hex_value = value.replace('[','',1).replace(']','',1)
    
    if '80' in hex_value:
        hex_value = value.replace('[','',1).replace(']','',1). replace('80','',1)
        
    value = int(hex_value,16)
    return value, hex_value
    
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

def make_new_text(file_path ,number_of_nop):
    
    global old_rawPointer
    global old_nextPointer
        
    pe = pefile.PE(file_path)
    pe_data = open(file_path, "rb").read()
        
    prev_section = None   
    
    for section in pe.sections:
        #if section.Name.strip(b'\x00') == b'.text' or section.Name.strip(b'\x00').upper() == b'CODE':
        if section.Name.strip(b'\x00').lower() in ['.text', 'text', 'code', '.code']:
            old_nextPointer = section.PointerToRawData
            text_section = section
            break
        prev_section = section

    if text_section is None or text_section.SizeOfRawData == 0:
        print("Error: .text section not found")
        return

    old_rawPointer = text_section.PointerToRawData
    old_size = text_section.Misc
    virtual_address = text_section.VirtualAddress
    image_base = pe.OPTIONAL_HEADER.ImageBase
    section_text = pe_data[text_section.PointerToRawData: text_section.PointerToRawData + text_section.Misc]
          
    #bitness = 64 if pe.FILE_HEADER.Machine == 0x8664 else 32
    
    if pe.FILE_HEADER.Machine == 0x8664:
        #bitness = 64
        decoder = Decoder(64, section_text, ip=image_base+virtual_address)
        bit = 64
        address_pattern_short = re.compile(r'\b,?[0-9A-Fa-f]{12}h\b|,?\[\b[0-9A-Fa-f]{12}h\b\]')
        address_pattern_long = re.compile(r'\b,?[0-9A-Fa-f]{16}h\b|,?\[\b[0-9A-Fa-f]{16}h\b\]')
        
    else:
        #bitness = 32
        decoder = Decoder(32, section_text, ip=image_base+virtual_address)
        bit = 32
        address_pattern_short = re.compile(r'\b,?[0-9A-Fa-f]{6}h\b|,?\[\b[0-9A-Fa-f]{6}h\b\]')
        address_pattern_long = re.compile(r'\b,?[0-9A-Fa-f]{8}h\b|,?\[\b[0-9A-Fa-f]{8}h\b\]')
    
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
    'E2': '0F85'  # loop
    }
    
    nop_cnt = 0
    increase_instr = 0
    
    jump_dict={}
    caller_callee_dict={}
    checking_target_address={}
    modified_address={}
    
    for instr in decoder:
        
        checker_80 = 0
        
        disasm = formatter.format(instr)
        op_code = instr.op_code()
        
        offsets = decoder.get_constant_offsets(instr)      
        
        present_instr = pe_data[text_section.PointerToRawData + (instr.ip-(image_base+virtual_address)):text_section.PointerToRawData + ((instr.next_ip)-(image_base+virtual_address))]
        present_address = (instr.ip+nop_cnt+increase_instr)
        
        modified_address[instr.ip] = (present_address)

                
        if ('int3' in disasm) or ('ret' in disasm) or ('nop' in disasm):
            new_text += present_instr
            continue

        if 'REL' not in code_to_string(instr.code): # 절대주소
            value = address_pattern_short.findall(str(instr))
            
            if value:
                value, hex_value = value_int_convert(value)
                
            else:
                saperator = [present_instr.hex()[i:i+2] for i in range(0, len(present_instr.hex()), 2)]
                
                if len(present_instr.hex()) == 14 and saperator[-1] =='80':
                    value = address_pattern_long.findall(str(instr))

                    value,hex_value = value_int_convert(value)

                    checker_80 = 1
                else:
                    value = 0
            
            if text_start <= value <= text_end:
                #print(hex(instr.ip),hex(present_address),instr, present_instr.hex(), instr.ip, present_address, type(instr.ip),code_to_string(instr.code),"|",increase_instr)
                caller_callee_dict[instr.ip] = value
                target_address = to_little_endian(hex_value)
                target_address +='00'
                op_code = present_instr.hex().replace(target_address.lower(),'')

                adding_nop_cnt, increace_instruction, increase_address = count_instructions(instr.ip, value, section_text, bit, (image_base+virtual_address),number_of_nop, jump_dict, nop_cnt, increase_instr, address_pattern_long)
                i_cnt = sum(increase_address.values())
                
                if instr.ip < value:
                    target_address = value + (nop_cnt + adding_nop_cnt + (increase_instr))+(i_cnt)

                if instr.ip > value:
                    if (len(increase_address) and (list(increase_address.keys())[0] == instr.ip)):
                        i_cnt = 0
                    
                    target_address = value + (nop_cnt - adding_nop_cnt - (i_cnt)) + increase_instr
                    
                #print("target_address : ",target_address, hex(target_address))
                operand = hex(target_address).replace('x','0',1) # target_address affset
                
                if len(operand)>8:
                    operand = operand[1:]
                    print("operand : ",operand, len(operand))
                    
                if len(operand)<8:
                    operand = '0'+operand
                    
                operand = to_little_endian(operand)
                #print("operand : ",operand)
                
                if checker_80 ==1:
                    op_code = present_instr.hex()[:6]
                    #print("checker_80 : ",checker_80, op_code)
                    new_ins = op_code+operand+'80'
                    new_ins = new_ins.replace('0080','80',1)
                    
                else: 
                    new_ins = op_code+operand
                
                #print("  new_ins : ",new_ins,'\n')
                mc_code =  bytes.fromhex((new_ins))
                new_text+= mc_code

                checking_target_address[present_address] = target_address

                if should_add_nop(str(instr)):
#                     if hex(instr.ip) in address_dict:
#                         continue

#                     else:
                    new_text += (b'\x90'*number_of_nop)
                    nop_cnt+=(1*number_of_nop)
                    continue
                else:
                    continue
                    
            else:

#                 if hex(instr.ip) in address_dict:
#                     new_text += present_instr
#                     continue

#                 else:
                new_text += present_instr
                if should_add_nop(str(instr)):
                    new_text += (b'\x90'*number_of_nop)
                    nop_cnt+=(1*number_of_nop) 
                    continue           
                else:
                    continue

        if 'REL' in code_to_string(instr.code):

            matches = address_pattern_long.findall(str(instr))
            
            address  = int(matches[0].replace('h',''),16)
            op_code = present_instr.hex()[:2]
            operand = present_instr.hex()[2:]
            ori_operand = operand
            present_address = (instr.ip+nop_cnt+increase_instr)

            if instr.ip < address:
                caller_callee_dict[instr.ip] = address
                #print("밑으로 뛰")
                if 'ptr' in str(instr) and len(operand)>8:
                    
                    op_code = present_instr.hex()[:4]
                    operand = present_instr.hex()[4:]
                    
                    
                operand = to_little_endian(operand)              
                int_operand = hex_to_signed_int(operand)
                adding_nop_cnt, increace_instruction, increase_address = count_instructions(instr.ip, address, section_text, bit, (image_base+virtual_address), number_of_nop, jump_dict, nop_cnt, increase_instr, address_pattern_long)
    
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
                
                new_ins = op_code+operand

                if len(present_instr.hex()) != len(new_ins):
                    if 'short' in str(instr) or 'loop' in str(instr):
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
                                

                            int_operand = target_address - present_address - new_ins_len

                            parm_operand = hex(int_operand).replace('0x','',1)
                            
                            if len(parm_operand)%2 !=0:
                                new_parm_operand = '0'+ parm_operand
                                parm_operand = new_parm_operand
  
                            new_operand = to_little_endian(parm_operand)

                            operand = new_operand + '0' * (8-len(new_operand))

                            increase_instr += new_ins_len - len(instr)
                            jump_dict[instr.ip] = int(new_ins_len - len(instr))
                            
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

                if should_add_nop(str(instr)):
                    if hex(instr.ip) in address_dict:
                        continue
                    else:
                        new_text += (b'\x90'*number_of_nop)
                        nop_cnt+=(1*number_of_nop)
                        continue
                else:
                    continue

            elif instr.ip > address:
                #print("위로 뛸꺼고")
                caller_callee_dict[instr.ip] = address
                if 'ptr' in str(instr) and len(operand)>8:
                    op_code = present_instr.hex()[:4]
                    operand = present_instr.hex()[4:]
                
                operand = to_little_endian(operand)
                int_operand = hex_to_signed_int(operand)

                adding_nop_cnt, increace_instruction, increase_address = count_instructions(address, instr.ip, section_text, bit, (image_base+virtual_address), number_of_nop, jump_dict, nop_cnt, increase_instr, address_pattern_long)
                present_address = (instr.ip  + nop_cnt + increase_instr)

                i_cnt = 0     
                i_cnt = sum(increase_address.values())
                
                if (len(increase_address) and (list(increase_address.keys())[0] == instr.ip)):
                    i_cnt = 0
                
                target_address = len(instr) + present_address + (int_operand - adding_nop_cnt - (i_cnt))
                
                offset = target_address - present_address - len(instr) 
                operand = negative_to_little_endian_hex(offset)
                new_ins = op_code+operand
      
                if len(present_instr.hex()) != len(new_ins):
                    if 'ff' in new_ins:
                        operand = operand.replace('ff','',)
                        new_ins = op_code+operand
                        
                    if 'short' in str(instr) or 'loop' in str(instr):    
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

                            int_operand = target_address - present_address - new_ins_len
                            new_operand = negative_to_little_endian_hex(int_operand)
                        
                            operand = new_operand + '0' * (8-len(new_operand))
                           
                            increase_instr += new_ins_len - len(instr)
                            jump_dict[instr.ip] = new_ins_len - len(instr)
                            
                        new_ins = op_code+operand                    

                mc_code =  bytes.fromhex((new_ins))
                new_text += mc_code
                checking_target_address[present_address] = target_address

                if should_add_nop(str(instr)):
                    if hex(instr.ip) in address_dict:
                        continue

                    else:
                        new_text += (b'\x90'*number_of_nop)
                        nop_cnt+=(1*number_of_nop)
                        continue
                else:
                    continue    
        else:
            print("나머지?? : ",instr.ip, instr)
            continue

    #print(f"[++] original .text section length : {text_section.Misc}")
    #print(f"[++] new .text section length : {len(new_text)}")

    return new_text, modified_address , caller_callee_dict, checking_target_address

def calc_offset(target_address, address, ori_operand, op_code, size):
    
    if address > target_address:
        #print(" up jump")
        new_operand = address - target_address - size #len(instr)
        operand = negative_to_little_endian_hex(new_operand)

    if address < target_address:
        #print(" down jump")
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
    
    new_address_to_ori_address = {v:k for k,v in modified_address.items()} # new address to original
    modifying_address = {}

    for caller,callee in checking_target_address.items():
        
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

    return modifying_address

def modify_instruction_at_address(binary_data, text_section, target_address, new_ins):
    relative_address = target_address - text_section.VirtualAddress
    binary_data = bytearray(binary_data)
    binary_data[text_section.PointerToRawData + relative_address : text_section.PointerToRawData + relative_address + len(new_ins)] = bytes.fromhex((new_ins))
    return binary_data

def is_direct_address(target, decoded_instructions):
    # Check for immediate values (which could indicate direct addresses)
    immediate_pattern = re.compile(r'\b0x[0-9A-Fa-f]+\b')
    for (offset, size, instruction, hexdump) in decoded_instructions:
        if offset == target:
            
            if bool(immediate_pattern.search(instruction)) and ('ff' not in hexdump):
                return "ABS", offset, instruction, hexdump, size
            else:
                return "REL", offset, instruction, hexdump, size
            
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
    print(modifying_address)
    
    if not modifying_address:
        return

    pe = pefile.PE(save_dir)
    pe_data = open(save_dir, "rb").read()

    prev_section = None   

    for section in pe.sections:
        if section.Name.strip(b'\x00') == b'.text' or section.Name.strip(b'\x00').upper() == b'CODE':
            old_nextPointer = section.PointerToRawData
            text_section = section
            break

        prev_section = section

    if text_section is None or text_section.SizeOfRawData == 0:
        print("Error: .text section not found")
        return

    image_base = pe.OPTIONAL_HEADER.ImageBase

    text_start = text_section.VirtualAddress + image_base
    text_end = text_start + text_section.Misc_VirtualSize

    binary_data = text_section.get_data()
    ori_binary_data = binary_data

    if pe.FILE_HEADER.Machine == 0x8664:
        bitness = 64
        address_pattern_short = re.compile(r'\b0x[0-9A-Fa-f]{12}\b|\[0x[0-9A-Fa-f]{12}\]')
        address_pattern_long = re.compile(r'\b0x[0-9A-Fa-f]{16}\b|\[0x[0-9A-Fa-f]{16}\]')
    else:
        bitness = 32
        address_pattern_short = re.compile(r'\b0x[0-9A-Fa-f]{6}\b|\[0x[0-9A-Fa-f]{6}\]')
        address_pattern_long = re.compile(r'\b0x[0-9A-Fa-f]{8}\b|\[0x[0-9A-Fa-f]{8}\]')

    decoded_instructions = decode_instructions(binary_data, text_start, bitness)

    for target, destination in modifying_address.items():
        checker_80 = 0
        #print("target : ",target, decoded_instructions)
        address_type, address, instrcution, hexdump, size = is_direct_address(target, decoded_instructions)

        instr_str = str(instrcution)
        present_instr = hexdump

        if 'REL' not in address_type: # 절대주소
            value = address_pattern_short.findall(instr_str)

            if not value:
                value = address_pattern_long.findall(instr_str)

                if len(present_instr) == 14 and present_instr[-2:] == '80':
                    checker_80 = 1

            if value:
                value, hex_value = value_int_convert(value)

            else:
                value = 0

            if text_start <= value <= text_end:
                caller_callee_dict[target] = value
                target_address = to_little_endian(hex_value) + '00'
                op_code = present_instr[:2]

                operand = hex(destination).replace('x','0',1) # target_address affset
                operand = to_little_endian(operand)

                if checker_80 == 1:
                    op_code = present_instr[:6]                    
                    new_ins = op_code+operand+'80'

                    if segment_prefix:
                        new_ins = segment_prefix+op_code+operand+'80'

                    new_ins = new_ins.replace('0080','80',1)

                else: 
                    new_ins = op_code+operand

        elif 'REL' in address_type: # 상대주소:
            op_code = present_instr[:2]
            operand = present_instr[2:]
            ori_operand = operand

            if len(operand)>8:
                op_code = present_instr[:4]
                operand = present_instr[4:]
                ori_operand = operand

            value = address_pattern_short.findall(instr_str)

            if value: #상대주소
                new_ins, op_code,operand = calc_offset(destination, address, ori_operand, op_code, size)

            else:
                value = address_pattern_long.findall(instr_str)
                if value: #상대주소
                    new_ins,op_code,operand  = calc_offset(destination, address, ori_operand, op_code, size)

        binary_data = modify_instruction_at_address(binary_data, text_section, target, new_ins)

    #new_text = binary_data
    print(f"[++] original .text section length : {text_section.Misc}")
    print(f"[++] new .text section length : {len(binary_data)}") 
    
    #print(ori_binary_data == binary_data)
    new_text = modify_headers(file_path, binary_data, fin = 1)
    save_dir = modify_section(file_path, new_text, save_dir, str(number_of_nop), fin = 1)
    modify_tramp(save_dir, modified_address, fin = 1)
    modify_rdata(save_dir, modified_address, fin = 1)
        
if __name__ == '__main__':
        
    sample_dir = '../sample/section_move_sample/'
    save_dir = '../sample/perturbated_sample/adding_nop/'
    
    samples = list_files_by_size(sample_dir)
    create_directory(save_dir)
    
    number_of_nop = 456
    
    for sample in samples:
        if '.ipynb' in sample or '.pickle' in sample or '.txt' in sample or '.zip' in sample:
            continue

        if 'PEview_new.exe' not in sample:
#         if 'hello_32_new.exe' not in sample:
            continue
        
        file_path = sample_dir+sample

        print(file_path)
                 
        new_text, modified_address, caller_callee_dict, checking_target_address = make_new_text(file_path, number_of_nop)
        print("len_new_text: ",len(new_text))

        if new_text is None:
            print(f"[+] Error : failed to make new_text section.") 
        else:
            new_text = modify_headers(file_path, new_text)
            save_dir = modify_section(file_path, new_text, save_dir,number_of_nop)
            modify_tramp(save_dir, modified_address)
            save_dir = modify_rdata(save_dir, modified_address)
            valid_address_check(file_path, save_dir, caller_callee_dict, checking_target_address, modified_address, str(number_of_nop))
            print("Done!!",sample)