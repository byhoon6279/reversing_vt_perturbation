#!/usr/bin/env python3z
from overlay_append import *
from perturb_pe_header import *
from modify_dos_header import *
from extend_dos_header import *
from dropper import *
from entry_point_extend import *
from code_randomization import *
from jmp_back_to_other_address import *
from add_section import *
from change_entrypoint import *
from entry_point_extend import *
from nop_insertion import *
from packing import *
from section_append import *
from filling_slack import *
from contents_shifting import *
from import_function_injection import *
import argparse
import os

def filter_numbers(numbers):
    unique_numbers = []
    num_ten = None

    for number in numbers:
        try:
            num = int(number)
            if 1 <= num <= 16 and num not in unique_numbers:
                if num == 10:
                    num_ten = num
                else:
                    unique_numbers.append(num)

        except ValueError:
            pass

    if num_ten is not None:
        unique_numbers.append(num_ten)

    return unique_numbers

def select_options():
    print('''
    *** Please select all options you want ***\n
    *** Please use this script in linux ***\n
    
    [1] Overlay Append 
    [2] Perturb Header Fields
    [3] Filling Slack Space 
    [4] Modifying DOS Header and Stub
    [5] Extend the DOS Header
    [6] Content shifting
    [7] Import Function Injection
    [8] Section Add
    [9] Section append
    [10] Packing
    [11] Change entry point
    [12] Dropper
    [13] Code Randomization
    [14] entry point extend
    [15] nop insertion
    [16] jmp/jmp back to other address 
    [Input Example] : 1 2 3 4 5 6 
    ''')

    select = input("> ").split()
    options = filter_numbers(select)

    return options

def patch_pe(filepath, options):
    data = bytearray(open(filepath, "rb").read())
    filename = os.path.basename(filepath)

    packing_enable = False
    for num in options:
        if num == 10:
            packing_enable = True
        else:
            data = execute_case(data,num)

    open(f"test/changed_{filename}", "wb").write(data)

    if packing_enable == True:
        pack_with_upx(f"test/changed_{filename}","packed.exe")

    print(f"[+] Patched Binary was created to \"changed_{filename}\"")
    return 
    
def execute_case(data,num):
    if num == 1:
        # Overlay Append
        print("== Overlay Append ==")
        append_data = input("append data ==> ").encode()
        print (append_data)
        new_data = overlay_append_dummy(data, append_data)
        return new_data 

    elif num == 2:
        # Perturb Header Fields
        print("== Perturb Header Fileds ==")
        section_name = input("Section name to Perturb ==> ")
        checksum = input("checksum to replace ==> ").encode()
        new_data = perturb_pe_header(data, section_name, checksum)
        return new_data

    elif num == 3:
        # Filling Slack Space 
        print("== Filling Slack Space ==")
        new_data = fill_slack(data) 
        return new_data

    elif num == 4:
        # Modifying DOS Header and Stub
        print("== Modifying DOS Header and Stub ==")
        new_data = modify_dos_header(data)
        return new_data

    elif num == 5:
        # Extend the DOS Header
        print("== Extend the DOS Header ==")
        code = input("Code to write in dos header ==> ").encode()
        new_data = extend_dos_stub(data, code) 
        return new_data

    elif num == 6:
        # Content shifting
        print("== Content Shifting ==")
        new_data = gap_sections(data)
        new_data = extend_and_shift_sections(data)
        return new_data

    elif num == 7:
        # Import Function Injection
        print("== Import Function Injection ==")
        cnt = input("Number of times to populate ==> ")
        info = []
        for i in cnt:
            value = {}
            funcname = input("Input function name to populate ==> ").encode()
            code = input("Input arbitrary x86 code to execute ==> ").encode()
            value["funcname"] = funcname
            value["nativecode"] = code
            info.append(value)

        new_data = iat_injection(data, info)
        return new_data

    elif num == 8:
        # Section Add
        print("== Section Add ==")
        section_name = input("Input Section name ==> ")
        section_data = input("Input Section data ==> ").encode()
        new_data = add_section(data, section_name, section_data, PERM.READ | PERM.WRITE | PERM.EXEC)
        return new_data 

    elif num == 9:
        # Section append
        print("== Section Append ==")
        data = section_append_unused(data)
        new_data = section_append_gap(data)
        return new_data

    elif num == 11:
        # Change entry point
        print("== Change entry point ==")
        entry_point = int(input("Entry point to replace ==> "))
        new_data = change_entry_point(data, entry_point)
        return new_data

    elif num == 12:
        # Dropper
        print("== Dropper ==")
        drop_binary = input("binary filename will be dropped ==> ")
        target_dir = input("filename with path will be placed in target host ==> ")
        drop_binary = bytearray(open(drop_binary, "rb").read())
        new_data = dropper(data, drop_binary, target_dir) 
        return new_data

    elif num == 13:
        # Code Randomization
        print("== Code Randomization ==")
        new_data = code_randomization(data)
        return new_data

    elif num == 14:
        # entry point extend
        print("== Entry point extend ==")
        section_name = input("Input Section name ==> ")
        section_rva = int(input("Input RVA value will be replaced ==> "))
        section_offset_value = int(input("Input offset value will be replaced ==> "))

        new_data = entry_point_extend(data, section_name, section_rva, section_offset_value)
        return new_data

    elif num == 15:
        # nop insertion
        print("== Nop insertion ==")
        optimization_level = int(input("Input Optimization level ( 0 [weak optimization] ~ 3 [strong optimization] )"))
        new_data = nop_insertion(data, optimization_level)
        return new_data

    elif num == 16:
        # jmp/jmp back to other address 
        print("jmp/jmp back to other address ")
        hook_ptr = int(input("Input poitner to hook ==> "))
        overlay_offset = int(input("Input Overlay file offsets to hook ==> "))
        new_data = jmp_back_to_other_address(data, hook_ptr, overlay_offset)
        return new_data

    else:
        raise ValueError(f"Case {num} is not defined")

if __name__ == '__main__': 
    parser = argparse.ArgumentParser(description='[Usage] main.py --input <target_exe>]')
    parser.add_argument('--input', required=True, type=str,help='[Usage] main.py --input <target_exe>]')

    args = parser.parse_args()

    filepath = args.input
    options = select_options()
    
    patch_pe(filepath, options)
