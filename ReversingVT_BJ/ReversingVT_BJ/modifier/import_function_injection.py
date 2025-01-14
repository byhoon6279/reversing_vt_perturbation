from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from add_section import * 
from iced_x86 import *
from overlay_append import *
from change_entrypoint import *
from pwn import *
import random
import string
import pefile

def btoi(data: bytes) -> int:
    return int.from_bytes(data, byteorder="little")


def itob4(data: int) -> bytes:
    return data.to_bytes(4, byteorder="little")


def itob2(data: int) -> bytes:
    return data.to_bytes(2, byteorder="little")

def search_section_header_by_name(data: bytes, section_name: bytes) -> int:
    pe_header_offset = btoi(data[0x3C:0x40])  # e_lfanew
    if data[pe_header_offset : pe_header_offset + 4] != b"PE\x00\x00":
        raise ValueError("Invalid PE header offset")

    section_header_start_offset = pe_header_offset + 0xf8
    total_number_of_section = btoi(data[pe_header_offset + 0x6 : pe_header_offset + 0x8])

    section_header_size = 0x28
    executable_section_list = []

    target = 0
    for i in range(total_number_of_section):
        cur_section_header = section_header_start_offset + i * section_header_size
        cur_section_name = bytes(data[cur_section_header : cur_section_header + 0x8])

        if cur_section_name.replace(b'\x00', b'') == section_name:
            return cur_section_header
    
    raise ValueError("Failed to find section header by name")

def gen_random_section_name(length: int) -> bytes:
    if length > 7:
        raise ValueError("length must be < 7")
    ascii_characters = string.ascii_letters + string.digits + string.punctuation
    random_ascii_string = ''.join(random.choice(ascii_characters) for _ in range(length))
    return b'.' + random_ascii_string.encode()

def make_assemble_jmp(jmp_target):
    '''
    0:  68 ef be ad de          push   0xdeadbeef
    5:  c3                      ret
    '''

    asm_bytes = b"\x68"
    asm_bytes += itob4(jmp_target)
    asm_bytes += b"\xc3"
    return asm_bytes
    
def make_assemble_call(call_target):
    '''
    0:  57                      push   edi
    1:  68 ef be ad de          push   0xdeadbeef
    6:  5f                      pop    edi
    7:  ff d7                   call   edi
    9:  5f                      pop    edi
    '''

    asm_bytes = b"\x57" # push edi
    asm_bytes += b"\x68" # push
    asm_bytes += itob4(call_target)
    asm_bytes += b"\x5f" # pop edi 
    asm_bytes += b'\xff\xd7' # call edi
    asm_bytes += b'\x5f' # pop edi
    return asm_bytes

def find_target_function_rva_with_funcname(data, target_func_name: bytes) -> int:
    pe_data = pefile.PE(data=data)
    for import_dll in pe_data.DIRECTORY_ENTRY_IMPORT:
        for api in import_dll.imports:
            if api.name == target_func_name:
                print(f"[+] Find {api.name} in {import_dll.dll} at {api.address:#x}")
                return api.address
    
    raise ValueError(f"Failed to find target function {target_func_name}")

def make_patch_iat_assembly(target_function_addr: int, arbitrary_code_addr: int) -> bytes:
    code = f'''
    mov dword ptr [{target_function_addr}], {arbitrary_code_addr}
    '''

    print(code)
    code = asm(code)
    return code

def iat_injection(data: bytes, overwrite_info: dict) -> bytes:
    """
    Adds an appropriate entry to the Import Address Table

    Args:
        data: Raw PE Binary bytes
        overwrite_info: structure
            iat_function_name: Target function name to populate
            arbitrary_code: arbitrary code to execute

    Returns:
        PE binary bytes with jmp back to other address applied
    """

    
    data = bytearray(data)

    # Get PE header offset
    pe_header_offset = btoi(data[0x3C:0x40])  # e_lfanew
    if data[pe_header_offset : pe_header_offset + 4] != b"PE\x00\x00":
        raise ValueError("Invalid PE header offset")

    # Disable IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE
    data[0xd6 : 0xd8] = itob2(0x8100)

    # grant write permission to .rdata
    rdata_section_header = search_section_header_by_name(data, b".rdata")
    characteristics = btoi(data[rdata_section_header + 0x24 : rdata_section_header + 0x28])

    # add WRITE_PERM
    characteristics |= 0x80000000
    data[rdata_section_header + 0x24 : rdata_section_header + 0x28] = itob4(characteristics)


    PE_image_base = btoi(data[pe_header_offset + 0x34: pe_header_offset + 0x38])

    AddressOfEntryPoint_offset = pe_header_offset + 0x28
    original_entry_point = btoi(data[AddressOfEntryPoint_offset : AddressOfEntryPoint_offset + 4])
    
    patch_iat_asm = b''
    for info in overwrite_info:
        random_section_name = gen_random_section_name(5)
        data = add_section(data, random_section_name.decode(), info["nativecode"], PERM.READ | PERM.EXEC)
        arbitrary_code_section_header = search_section_header_by_name(data, random_section_name)
        RVA__arbitrary_code_section = btoi(data[arbitrary_code_section_header + 0xc : arbitrary_code_section_header + 0x10])

        RVA_target_function = find_target_function_rva_with_funcname(data, info["funcname"])
        patch_iat_asm += make_patch_iat_assembly(RVA_target_function, PE_image_base + RVA__arbitrary_code_section)
    
    patch_iat_asm += make_assemble_jmp(PE_image_base + original_entry_point)
    data = add_section(data, ".ddd", patch_iat_asm, PERM.READ | PERM.EXEC)
    patch_iat_section_header = search_section_header_by_name(data, b".ddd")
    RVA__patch_iat_section = btoi(data[patch_iat_section_header + 0xc : patch_iat_section_header + 0x10])

    data = change_entry_point(data, RVA__patch_iat_section)
    return data

if __name__ == '__main__':
    data = bytearray(open("test/sample.exe", "rb").read())

    arbitrary_code = b"\xcc" * 0x100
    value = [
        {"funcname" : b"GetProcAddress", "nativecode" : b"\xcc" * 0x100},
        {"funcname" : b"GetCurrentThreadId", "nativecode" : b"\x90" * 0x100},
    ]
    new_data = iat_injection(data, value)
    open("test/sample_new.exe", "wb").write(new_data)
