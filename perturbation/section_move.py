import os
import sys
import pefile
import struct
import capstone
import random
import string

from functools import lru_cache
from math import ceil
from enum import IntEnum
from add_section import *

from dataclasses import dataclass, field
from typing import Dict, List, Union

import logging

# Setup logging configuration
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

@dataclass
class ImportTableEntry:
    OriginalFirstThunk: int # Import Name Table's RVA
    TimeDateStamp: int      # TimeStamp
    ForwarderChain: int     # Forwarderchain index
    Name: int               # DLL Name's RVA
    FirstThunk: int         # Import Address Table's RVA

@dataclass
class ImportAddressTableEntry:
    offset: int
    entry_data: bytes

@dataclass
class ImportNameTableEntry:
    offset: int
    entry_data: bytes

@dataclass
class ParsedImportTables:
    import_table: Dict[str, ImportTableEntry] = field(default_factory=dict)
    import_address_table: Dict[int, ImportAddressTableEntry] = field(default_factory=dict)
    import_name_table: Dict[str, ImportNameTableEntry] = field(default_factory=dict)
    import_table_section_name: str = None
    import_address_table_section_name: str = None

bound_import_rva = 0
bound_import_size = 0
bound_import_data = 0

@dataclass
class SectionInfo:
    name: str
    virtual_address: int
    virtual_size: int
    raw_data_offset: int
    raw_data_size: int
    characteristics: int

    @property
    def section_start(self) -> int:
        return self.virtual_address

    @property
    def section_end(self) -> int:
        return self.virtual_address + max(self.virtual_size, self.raw_data_size)

    @property
    def is_executable(self) -> bool:
        characteristics_be = int.from_bytes(self.characteristics.to_bytes(4, 'little'), 'big')
        executable = (characteristics_be & 0x20000000) != 0
        return executable


def is_in_executable_section(pe, rva):
    for section in pe.sections:
        if (section.VirtualAddress <= rva < section.VirtualAddress + section.Misc_VirtualSize) and (section.Characteristics & 0x20000000):
            return True
    return False


def check_import_tables_in_executable_section(pe) -> Union[bool, ParsedImportTables]:
    all_in_executable = True
    parsed_tables = ParsedImportTables()

    # Check the IMPORT TABLE RVA and IAT RVA
    import_table_rva = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']].VirtualAddress
    import_address_table_rva = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IAT']].VirtualAddress

    if not is_in_executable_section(pe, import_table_rva):
        # print(f"IMPORT TABLE at RVA {hex(import_table_rva)} is NOT in an executable section.")
        all_in_executable = False
    else:
        print(f"IMPORT TABLE at RVA {hex(import_table_rva)} is in an executable section.")

    if not is_in_executable_section(pe, import_address_table_rva):
        # print(f"IAT at RVA {hex(import_address_table_rva)} is NOT in an executable section.")
        all_in_executable = False
    else:
        print(f"IAT at RVA {hex(import_address_table_rva)} is in an executable section.")

    # Parse the IMPORT TABLE (IDT)
    import_table_offset = pe.get_offset_from_rva(import_table_rva)
    while True:
        descriptor_data = pe.get_data(import_table_offset, 20)
        if all(b == 0 for b in descriptor_data):
            break

        descriptor = pefile.Structure(pe.__IMAGE_IMPORT_DESCRIPTOR_format__, file_offset=import_table_offset)
        descriptor.__unpack__(descriptor_data)

        dll_name_rva = descriptor.Name
        dll_name_offset = pe.get_offset_from_rva(dll_name_rva)
        dll_name = pe.get_string_at_rva(dll_name_rva)

        # Store the ImportTableEntry
        parsed_tables.import_table[dll_name] = ImportTableEntry(
            OriginalFirstThunk=descriptor.OriginalFirstThunk,
            TimeDateStamp=descriptor.TimeDateStamp,
            ForwarderChain=descriptor.ForwarderChain,
            Name=descriptor.Name,
            FirstThunk=descriptor.FirstThunk
        )

        # Parse the INT (Original First Thunk)
        if descriptor.OriginalFirstThunk:
            original_first_thunk_offset = pe.get_offset_from_rva(descriptor.OriginalFirstThunk)
            int_entries = []
            while True:
                int_entry = int.from_bytes(pe.get_data(original_first_thunk_offset, 4), byteorder='little')
                if int_entry == 0:
                    break
                
                parsed_tables.import_name_table[original_first_thunk_offset] = ImportNameTableEntry(
                    offset=original_first_thunk_offset,
                    entry_data=int_entry.to_bytes(4, byteorder='little')
                )
                original_first_thunk_offset += 4
        
        import_table_offset += 20
    
    # Parse the IMPORT ADDRESS TABLE (IAT)
    if import_address_table_rva:
        iat_offset = pe.get_offset_from_rva(import_address_table_rva)
        while True:
            iat_entry_size = 8 if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64'] else 4
            iat_entry_data = pe.get_data(iat_offset, iat_entry_size)
            if int.from_bytes(iat_entry_data, byteorder='little') == 0:  # End of the IAT
                break

            parsed_tables.import_address_table[iat_offset] = ImportAddressTableEntry(
                offset=iat_offset,
                entry_data=iat_entry_data
            )
            iat_offset += iat_entry_size # Move to the next IAT entry

    return all_in_executable, parsed_tables


def adjust_parsed_tables(parsed_tables, offset_diff):
    # Adjust Import Table Entries (IDT)
    for dll_name, entry in parsed_tables.import_table.items():
        if entry.OriginalFirstThunk != 0:
            entry.OriginalFirstThunk += offset_diff
            print(f"Adjusted OriginalFirstThunk RVA for {dll_name}: {hex(entry.OriginalFirstThunk)}")  # Debugging output
        if entry.Name != 0:
            entry.Name += offset_diff
            print(f"Adjusted Name RVA for {dll_name}: {hex(entry.Name)}")  # Debugging output
        if entry.FirstThunk != 0:
            entry.FirstThunk += offset_diff
            print(f"Adjusted FirstThunk RVA for {dll_name}: {hex(entry.FirstThunk)}")  # Debugging output
    
    # Adjust Import Name Table Entries (INT)
    adjusted_import_name_table_entries = {}
    ordinal_indices = set()
    current_index = 0

    for offset, entry in parsed_tables.import_name_table.items():
        new_offset = offset + offset_diff
        entry_data_value = int.from_bytes(entry.entry_data, byteorder='little')

        if is_ordinal(entry_data_value):
            ordinal_indices.add(current_index)
            # print(f"INT entry at offset {hex(offset)} is an Ordinal: {hex(entry_data_value)}")
            adjusted_import_name_table_entries[new_offset] = ImportNameTableEntry(
                offset=new_offset,
                entry_data=entry_data_value.to_bytes(4, byteorder='little')
            )
        else:
            entry_data_value += offset_diff
            adjusted_import_name_table_entries[new_offset] = ImportNameTableEntry(
                offset=new_offset,
                entry_data=entry_data_value.to_bytes(4, byteorder='little')
            )
            # print(f"Adjusted INT entry at new offset {hex(new_offset)}: {hex(entry_data_value)}")
        
        current_index += 1
    
    parsed_tables.import_name_table.clear()
    parsed_tables.import_name_table.update(adjusted_import_name_table_entries)

    # Adjust Import Address Table Entries
    adjusted_import_address_table_entries = {}
    current_index = 0

    for offset, entry in parsed_tables.import_address_table.items():
        new_offset = offset + offset_diff
        if current_index in ordinal_indices:
            # print(f"IAT entry at offset {hex(offset)} corresponds to an Ordinal, not updating.")
            adjusted_import_address_table_entries[new_offset] = ImportAddressTableEntry(
                offset=new_offset,
                entry_data=entry_data_value.to_bytes(4, byteorder='little')
            )
        else:
            entry_data_value = int.from_bytes(entry.entry_data, byteorder='little') + offset_diff
            adjusted_import_address_table_entries[new_offset] = ImportAddressTableEntry(
                offset=new_offset,
                entry_data=entry_data_value.to_bytes(4, byteorder='little')
            )
        
        current_index += 1
    
    parsed_tables.import_address_table.clear()
    parsed_tables.import_address_table.update(adjusted_import_address_table_entries)

    return parsed_tables


def update_pe_with_parsed_tables(cloned_data, cloned_pe, parsed_tables):
    # Convert cloned_data to bytearray if it's not already
    cloned_data = bytearray(cloned_data)

    # Reflect the changes back to the PE structure
    import_table_rva = cloned_pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']].VirtualAddress
    import_table_offset = cloned_pe.get_offset_from_rva(import_table_rva)
    # print(f"import table offset: {hex(import_table_offset)}")
    
    for dll_name, entry in parsed_tables.import_table.items():
        # Locate the IMAGE_IMPORT_DESCRIPTOR entry for the DLL
        for i in range(0, len(parsed_tables.import_table) * 20, 20):  # 20 bytes per IMAGE_IMPORT_DESCRIPTOR entry
            current_name_rva = int.from_bytes(cloned_data[import_table_offset + i + 12:import_table_offset + i + 16], 'little')
            # print(f"Checking entry {i//20 + 1}: current_name_rva = {hex(current_name_rva)}, entry name: {hex(entry.Name)}")
            
            if entry.OriginalFirstThunk:
                cloned_data[import_table_offset + i:import_table_offset + i + 4] = struct.pack('<I', entry.OriginalFirstThunk)
                # print(f"Updated OriginalFirstThunk for {dll_name} at offset {hex(import_table_offset + i)}: {hex(entry.OriginalFirstThunk)}")

            if entry.Name:
                cloned_data[import_table_offset + i + 12:import_table_offset + i + 16] = struct.pack('<I', entry.Name)
                # print(f"Updated Name for {dll_name} at offset {hex(import_table_offset + i + 12)}: {hex(entry.Name)}")

            if entry.FirstThunk:
                cloned_data[import_table_offset + i + 16:import_table_offset + i + 20] = struct.pack('<I', entry.FirstThunk)
                # print(f"Updated FirstThunk for {dll_name} at offset {hex(import_table_offset + i + 16)}: {hex(entry.FirstThunk)}")
        
    # Update IAT and INT entries similarly
    for offset, entry in parsed_tables.import_address_table.items():
        cloned_data[offset:offset + len(entry.entry_data)] = entry.entry_data
        # print(f"Updated IAT entry at offset {hex(offset)} with data: {entry.entry_data.hex()}")

    for offset, entry in parsed_tables.import_name_table.items():
        cloned_data[offset:offset + len(entry.entry_data)] = entry.entry_data
        # print(f"Updated INT entry at offset {hex(offset)} with data: {entry.entry_data.hex()}")

    return cloned_data


def is_ordinal(entry_value):
    """
    Check if the given INT or IAT entry value indicates an Ordinal.

    Args:
        entry_value (int): The value of the INT or IAT entry.

    Returns:
        bool: True if the entry is an Ordinal, False otherwise.
    """
    # Ordinal if the highest bit is set
    return (entry_value & 0x80000000) != 0


def restore_bound_import_directory(data: bytes, bound_import_data: bytes) -> bytes:
    pe = pefile.PE(data=data)

    # Print the Bound Import Directory data to verify parsing
    print(f"Restoring Bound Import Directory Data: {bound_import_data.hex()}")

    # calculate the end of the last section header + padding
    section_table_offset = pe.DOS_HEADER.e_lfanew + 0x18 + pe.FILE_HEADER.SizeOfOptionalHeader
    section_count = pe.FILE_HEADER.NumberOfSections
    last_section_offset = section_table_offset + section_count * 0x28
    padding_start = last_section_offset

    # calculate where the padding space ends, taking into account the FileAlignment
    padding_end = (padding_start + pe.OPTIONAL_HEADER.FileAlignment - 1) & ~(pe.OPTIONAL_HEADER.FileAlignment - 1)

    # Ensure there's enough space in the padding area
    if len(bound_import_data) > (padding_end - padding_start):
        raise ValueError("Not enough space in padding area to restore BOUND IMPORT DIRECTORY.")
    
    # Insert Bound Import Directory into the padding area
    restored_data = bytearray(data)
    for i in range(len(bound_import_data)):
        restored_data[padding_start + i] = bound_import_data[i]

    pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT']].VirtualAddress = padding_start
    pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT']].Size = len(bound_import_data)

    # Calculate the offset of the Data Directory within the PE header
    data_directory_offset = (
        pe.DOS_HEADER.e_lfanew
        + 0x18  # PE Signature and File Header
        + pe.FILE_HEADER.SizeOfOptionalHeader  # Optional Header Size
        - 0x80  # Adjusting to the start of Data Directory
        + pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT'] * 8  # Offset within Data Directory array
    )

    # Update the Data Directory in the PE header
    restored_data[data_directory_offset:data_directory_offset + 4] = struct.pack("<I", padding_start)
    restored_data[data_directory_offset + 4:data_directory_offset + 8] = struct.pack("<I", len(bound_import_data))

    # Verify that the data was correctly written to the new location
    written_data = restored_data[padding_start:padding_start + len(bound_import_data)]
    print(f"Restored Bound Import Directory Data at new offset ({hex(padding_start)}): {written_data.hex()}")

    return bytes(restored_data)


def generate_random_string(length=8):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))


def safe_disasm(data, va, size, mode):
    md = capstone.Cs(capstone.CS_ARCH_X86, mode)
    md.detail = True
    end_va = va + size
    offset = 0
    while va + offset < end_va:
        try:
            code = data[offset:]            
            instructions = md.disasm(code, va + offset)
            instruction = next(instructions, None)
            if instruction is None:
                print(f"No valid instruction found at offset {offset}, trying next byte...")
                offset += 1
                continue
                
            yield instruction
            offset += instruction.size
                
        except capstone.CsError as e:
            print(f"Capstone decoding error at offset {hex(va + offset)}: {str(e)}")
            offset += 1


def get_disassembled_instructions(data, dst_section_name):
    pe = pefile.PE(data=data)
    dst_section = next((section for section in pe.sections if section.Name.decode('utf-8').rstrip('\x00') == dst_section_name), None)
    
    if dst_section is None:
        raise ValueError(f"No section named {dst_section_name} found")
        
    # Determine the correct mode based on the architecture
    cs_arch = capstone.CS_ARCH_X86
    cs_mode = capstone.CS_MODE_64 if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64'] else capstone.CS_MODE_32
    md = capstone.Cs(cs_arch, cs_mode)
    md.detail = True

    # Call safe_disasm to disassemble the data from the destination section
    instructions = safe_disasm(data[dst_section.PointerToRawData:dst_section.PointerToRawData + dst_section.SizeOfRawData], pe.OPTIONAL_HEADER.ImageBase + dst_section.VirtualAddress,
                               dst_section.SizeOfRawData,
                               cs_mode )
    return instructions


def hexify_byte_list(byte_list):
    return ''.join(format(b, '02x') for b in byte_list)

#def clone_section(data: bytes, new_section_name: str, clone_from_name: str) -> bytes:
def clone_section(data: bytes, new_section_name: str) -> bytes:
    
    pe = pefile.PE(data=data)
    global bound_import_rva, bound_import_size, bound_import_data
    
    # Check for Bound Import Directory and backup its RVA and Size
    bound_import_rva = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT']].VirtualAddress
    bound_import_size = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT']].Size

    if bound_import_rva != 0 and bound_import_size != 0:
        bound_import_data = pe.get_memory_mapped_image()[bound_import_rva:bound_import_rva + bound_import_size]
        print(f"Before adding section:\nBound Import Directory Data: {bound_import_data.hex()}")
    else:
        bound_import_data = None
        print("No Bound Import Directory found.")
    
    cloned_section = None
    section_name = None

    if pe.FILE_HEADER.Machine == 0x8664:
        return cloned_section, section_name, str(64)
    
    # Find the section to clone from by its name
    #source_section = next((section for section in pe.sections if section.Name.decode('utf-8').rstrip('\x00') == clone_from_name), None)
    text_section = None
    
    for section in pe.sections:
        section_name = section.Name.decode().strip('\x00').lower()
        if section_name in ['.text', 'text', 'code', '.code']:
            source_section = section
            section_name=section.Name.decode().strip('\x00')
            break
#         if section.Name.decode().strip('\x00') == '.text':
#             source_section = section
#             section_name=section.Name.decode().strip('\x00')
#             break
#         if section.Name.decode().strip('\x00') == 'CODE':
#             source_section = section
#             section_name=section.Name.decode().strip('\x00')
#             break
#         if section.Name.decode().strip('\x00') == 'code':
#             source_section = section
#             section_name=section.Name.decode().strip('\x00')
#             break
            
    # Extract the data from the section to be cloned
    source_data = data[source_section.PointerToRawData:source_section.PointerToRawData + source_section.SizeOfRawData]
    
    #source_data = data[section.PointerToRawData:section.PointerToRawData + section.SizeOfRawData]
    source_perms = (PERM.EXEC if source_section.Characteristics & 0x20000000 else 0) | \
    (PERM.READ if source_section.Characteristics & 0x40000000 else 0) | \
    (PERM.WRITE if source_section.Characteristics & 0x80000000 else 0) 

  # Add a new section with the data from the source section
  # The permissions for the new section are passed as an argument
    cloned_section = add_section(data, new_section_name, source_data, source_perms)
    
    # After adding section, check the Bound Import Directory again
    pe_after = pefile.PE(data=cloned_section)
    bound_import_rva_after = pe_after.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT']].VirtualAddress
    bound_import_size_after = pe_after.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT']].Size

    print(f"After adding section:\nBound Import Directory RVA: {hex(bound_import_rva_after)}, Size: {bound_import_size_after}")

    # Check if the Bound Import Directory has been overwritten
    if bound_import_rva != bound_import_rva_after or bound_import_size != bound_import_size_after:
        bound_import_data_after = pe_after.get_memory_mapped_image()[bound_import_rva_after:bound_import_rva_after + bound_import_size_after]
        print(f"After adding section:\nBound Import Directory Data: {bound_import_data_after.hex()}")
    else:
        bound_import_data_after = None
        print("After adding section:\nNo Bound Import Directory found.")
    
    # Check if the Bound Import Directory has been overwritten
    if bound_import_data != bound_import_data_after:
        print("Warning: Bound Import Directory data may have been overwritten!")
        if bound_import_data:
            print("Attempting to restore Bound Import Directory...")
            restored_data = restore_bound_import_directory(cloned_section, bound_import_data)
            return restored_data, section_name, str(32)

    return cloned_section, section_name, str(32)


def modify_reloc_section(data: bytes, text_section_name: str, new_section_name: str) -> bytes:
    pe = pefile.PE(data=data)
    modifiable_data = bytearray(data)
    
    # Locate the code section to find its VirtualAddress
    text_section = next((section for section in pe.sections if section.Name.decode('utf-8').rstrip('\x00') == text_section_name), None)
    
    if text_section is None:
        raise ValueError(f"No section named {text_section_name} found")
    text_va = text_section.VirtualAddress
    
    # Locate the new section to get its VirtualAddress
    new_section = next((section for section in pe.sections if section.Name.decode('utf-8').rstrip('\x00') == new_section_name), None)
    if new_section is None:
        raise ValueError(f"No section named {new_section_name} found")
    new_va = new_section.VirtualAddress
    
    # Locate the .reloc section
    reloc_section = next((section for section in pe.sections if section.Name.decode('utf-8').rstrip('\x00') == '.reloc'), None)
    if reloc_section is None:
        # raise ValueError('No .reloc section found')
        return modifiable_data

    reloc_data = modifiable_data[reloc_section.PointerToRawData:reloc_section.PointerToRawData + reloc_section.SizeOfRawData]
    # Check if the first entry in the .reloc section matches the VirtualAddress of the code section
    # How to find the RelocTable? NT_HEADER - Optional Header - DataDirArray - BaseRelocationTable.VirtualAddress & Size
    # How to parse the RelocTable? RelocTable - BaseReloc[index].VirtualAddress & SizeOfBlock
    # BaseReloc[i+1]'s VA is BaseReloc[i].VirtualAddress + BaseReloc[i].SizeOfBlock
    
    index = 0
    while index < len(reloc_data):
        reloc_va = int.from_bytes(reloc_data[index:index + 4], 'little')
        block_size = int.from_bytes(reloc_data[index + 4:index + 8], 'little')
        
        if block_size == 0:
            break

        if reloc_va == text_va:
            modifiable_data[reloc_section.PointerToRawData + index:reloc_section.PointerToRawData + index + 4] = new_va.to_bytes(4, 'little')

        index += block_size
    
    return modifiable_data


def insert_trampoline_code(data: bytes, src_section_name:str, dst_section_name: str) -> bytes:
    pe = pefile.PE(data=data)
    # Locate the code section
    text_section = next((section for section in pe.sections if section.Name.decode('utf-8').rstrip('\x00') == src_section_name), None)
    if text_section is None:
        raise ValueError("No executable section found")
        
    inserted_data = bytearray(data)
    
    # Fill the code section with NOPs
    nop_area = bytes([0x90] * text_section.SizeOfRawData)
    inserted_data[text_section.PointerToRawData:text_section.PointerToRawData + text_section.SizeOfRawData] = nop_area
    
    # Locate the .newsection section
    new_section = next((section for section in pe.sections if section.Name.decode('utf-8').rstrip('\x00') == dst_section_name), None)
    if new_section is None:
        raise ValueError(f"No section named {dst_section_name} found")
        
    entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    text_section_start_va = text_section.VirtualAddress
    entry_point_offset = entry_point - text_section_start_va
    
    # Calculate the relative virtual address (RVA) of the jump destination
    jump_destination_rva = new_section.VirtualAddress + entry_point_offset

    # Construct the jump instruction to the new entry point
    # For example, using a direct jump which is 5 bytes in x86 (E9 xx xx xx xx)
    # Calculate the offset for the jump instruction
    offset = jump_destination_rva - (text_section.VirtualAddress + entry_point_offset + 5)
    jump_instruction = b'\xE9' + offset.to_bytes(4, byteorder='little', signed=True)
    
    # Place the jump instruction at the start of the code section
    text_section_entry_point_raw = text_section.PointerToRawData + entry_point_offset
    inserted_data[text_section_entry_point_raw:text_section_entry_point_raw + 5] = jump_instruction
    
    return inserted_data


def adjust_instruction_offsets(data: bytes, src_section_name: str, dst_section_name: str, instructions):
    pe = pefile.PE(data=data)
    # Get source and destination section ranges
    src_section = next((s for s in pe.sections if s.Name.decode().strip('\x00') == src_section_name), None)
    dst_section = next((s for s in pe.sections if s.Name.decode().strip('\x00') == dst_section_name), None)
    
    if src_section is None or dst_section is None:
        raise ValueError(f"One of the sections {src_section_name}, {dst_section_name} not found")
        
    # Calculate the offset difference between the sections
    offset_diff = (dst_section.VirtualAddress + pe.OPTIONAL_HEADER.ImageBase) - (src_section.VirtualAddress + pe.OPTIONAL_HEADER.ImageBase)
    
    # Adjust instructions with relative addressing pointing to dst_section
    adjusted_data = bytearray(data)
    print("Disassembling executable section:")
    print(instructions)
    for ins in instructions:
        for op in ins.operands:
            if op.type == capstone.CS_OP_IMM:
                imm_value = op.imm
                if (pe.OPTIONAL_HEADER.ImageBase + src_section.VirtualAddress) <= imm_value < (pe.OPTIONAL_HEADER.ImageBase + src_section.VirtualAddress + src_section.Misc_VirtualSize):
                    if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386']:
                        imm_size = 4
                    elif pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']:
                        imm_size = 8 if op.size == 64 else 4  # Adjust based on operand size
                        # imm_size = 4 if op.size == 32 else 8
                        
                    imm_offset = ins.address - (dst_section.VirtualAddress + pe.OPTIONAL_HEADER.ImageBase) + (ins.size - imm_size)
                    new_imm_value = imm_value + offset_diff
                    adjusted_data[dst_section.PointerToRawData + imm_offset:dst_section.PointerToRawData + imm_offset + imm_size] = new_imm_value.to_bytes(imm_size, byteorder='little', signed=True)
                    print(f"Updated Address: {hex(ins.address)}, Mnemonic: {ins.mnemonic}, Original Target: {hex(imm_value)}, Updated Target: {hex(new_imm_value)}")
    
        if ins.mnemonic == "mov" and ins.operands[0].type == 3 and ins.operands[1].type == 2: # capstone.CS_OP_MEM and capstone.CS_OP_IMM
            offset_value = ins.operands[0].mem.disp
            imm_value = ins.operands[1].imm
            print(f"Detected instruction: {ins.mnemonic} {ins.op_str} at address {hex(ins.address)} with offset [ebp+{hex(offset_value)}], immediate value {hex(imm_value)}")

            if (imm_value & 0xFF000000) == 0x80000000:
                lower_3_bytes = imm_value & 0xFFFFFF
                src_start = pe.OPTIONAL_HEADER.ImageBase + src_section.VirtualAddress
                src_end = src_start + src_section.Misc_VirtualSize
                
                if src_start <= lower_3_bytes < src_end:
                    new_imm_value = imm_value + offset_diff
                    imm_size = 4

                    # Ensure new_imm_value is within 4-byte range
                    new_imm_value &= 0xFFFFFFFF

                    imm_offset = ins.address - (dst_section.VirtualAddress + pe.OPTIONAL_HEADER.ImageBase) + (ins.size - imm_size)
                    adjusted_data[dst_section.PointerToRawData + imm_offset:dst_section.PointerToRawData + imm_offset + imm_size] = new_imm_value.to_bytes(imm_size, byteorder='little', signed=False)
                    print(f"Updated immediate value from {hex(imm_value)} to {hex(new_imm_value)}")
    
    
    # Adjust data section with relative addressing pointing to dst_section
    for section in pe.sections:
        if section.Name.decode().strip('\x00') in ['.data', '.rdata', 'DATA', 'data', 'const']: # add malware's custom section name if you want
            print(f"Scanning {section.Name.decode().strip()} for offsets pointing to {src_section_name}")
            file_offset_start = section.PointerToRawData
            file_offset_end = file_offset_start + section.SizeOfRawData
            
            # scan each 4-byte (assuming 32-bit offsets) or 8-byte (for 64-bit) block
            offset_size = 4 if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386'] else 8
            
            # for 32-bit pefile
            if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386']:
                for offset in range(file_offset_start, file_offset_end, offset_size):
                    potential_pointer = int.from_bytes(adjusted_data[offset:offset+offset_size], byteorder='little')
                    if src_section.VirtualAddress + pe.OPTIONAL_HEADER.ImageBase <= potential_pointer < src_section.VirtualAddress + pe.OPTIONAL_HEADER.ImageBase + src_section.Misc_VirtualSize:
                        new_pointer = potential_pointer + offset_diff
                        print(f"Fix pointer at raw offset {hex(offset)}: from {hex(potential_pointer)} to {hex(new_pointer)}")
                        adjusted_data[offset:offset+offset_size] = new_pointer.to_bytes(offset_size, byteorder='little')
                print("32bit done")            
            # for 64-bit pefile
            else:
                for offset in range(file_offset_start, file_offset_end):
                    for size in [4, 8]:
                        if offset + size > file_offset_end:
                            continue
                            
                        potential_pointer = int.from_bytes(adjusted_data[offset:offset + size], byteorder='little')
                        if src_section.VirtualAddress + pe.OPTIONAL_HEADER.ImageBase <= potential_pointer < src_section.VirtualAddress + pe.OPTIONAL_HEADER.ImageBase + src_section.Misc_VirtualSize:
                            new_pointer = potential_pointer + offset_diff
                            print(f"Fix pointer at raw offset {hex(offset)}: from {hex(potential_pointer)} to {hex(new_pointer)}")
                            adjusted_data[offset:offset + size] = new_pointer.to_bytes(size, byteorder='little')
                            # if section.VirtualAddress + pe.OPTIONAL_HEADER.ImageBase <= potential_pointer < section.VirtualAddress + pe.OPTIONAL_HEADER.ImageBase + section.Misc_VirtualSize:
                            #   data_offset = potential_pointer - pe.OPTIONAL_HEADER.ImageBase
                            #   actual_data = adjusted_data[data_offset:data_offset + size]
                            #   print(f"Data at pointer in own section {hex(potential_pointer)}: {actual_data.hex()} {size}")
    print("Done")                        
    return adjusted_data


def adjust_rip_relative_offsets(data: bytes, src_section_name: str, dst_section_name: str, instructions):
    pe = pefile.PE(data=data)
    
    src_section = next((s for s in pe.sections if s.Name.decode().strip('\x00') == src_section_name), None)
    dst_section = next((s for s in pe.sections if s.Name.decode().strip('\x00') == dst_section_name), None)
    
    if not src_section or not dst_section:
        raise ValueError(f"Could not find specified sections: {src_section_name}, {dst_section_name}")
        
    adjusted_data = bytearray(data)
    
    dst_section_start = pe.OPTIONAL_HEADER.ImageBase + dst_section.VirtualAddress
    dst_section_end = dst_section_start + dst_section.SizeOfRawData
    print("Disassembling executable section for rip-relative offsets")
    for ins in instructions:
        for op in ins.operands:
            if op.type == capstone.x86.X86_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP:
                src_next_rip = src_section.VirtualAddress - dst_section.VirtualAddress + ins.address + ins.size
                dst_next_rip = ins.address + ins.size
                
                original_target = src_next_rip + op.mem.disp
                new_target = dst_next_rip + op.mem.disp
                
                if dst_section_start <= new_target < dst_section_end:
                    continue
                    
                new_offset = original_target - dst_next_rip
                new_offset = (new_offset + 0x80000000) % 0x100000000 - 0x80000000
                
                # Determine the actual byte position for the offset within the instruction
                mod = (ins.modrm & 0xC0) >> 6
                disp_size = 0
                if mod == 0x01:
                    disp_size = 1 # 1 byte
                elif mod == 0x02:
                    disp_size = 4 # 4 byte
                elif mod == 0x00:
                    if ins.sib and ((ins.sib & 0x07) != 0x05):
                        disp_size = 0
                    else:
                        disp_size = 4
                        
                disp_bytes = op.mem.disp.to_bytes(disp_size, byteorder='little', signed=True)
                disp_hex = disp_bytes.hex()
                byte_seq = ins.bytes.hex()
                pos_in_bytes = byte_seq.find(disp_hex) // 2
                
                new_disp_bytes = new_offset.to_bytes(disp_size, byteorder='little', signed=True)
                start_position = dst_section.PointerToRawData + (ins.address - pe.OPTIONAL_HEADER.ImageBase - dst_section.VirtualAddress) + pos_in_bytes
                new_target = dst_next_rip + new_offset
                print(f"{ins.bytes.hex()} Instruction at {hex(ins.address)}: {ins.mnemonic} {ins.op_str} || Orig Tgt: {hex(original_target)}], New Tgt: {hex(new_target)} || NewOffset: {hex(new_offset)} || Disp hex value: {disp_hex} ==> {new_disp_bytes.hex()}")
                adjusted_data[start_position:start_position + disp_size] = new_disp_bytes
                
    return adjusted_data


def rename_new_section(data: bytes, ori_section_name: str = None) -> bytes:
    data = bytearray(data)

    pe = pefile.PE(data=data)

    # Find the index of the last section
    last_section_index = len(pe.sections) - 1
    
    
    for section_index, section in enumerate(pe.sections):
        section_name = section.Name.decode().strip('\x00')
        section_name = section_name.lower()
        if section_name in ['.text', 'text', 'code','.code']:
            last_section_index = section_index
            break
    
    
    # Get the name of the last section
    new_section_name = pe.sections[last_section_index].Name.decode().strip('\x00')

    # Change the name of the last section to a random string
    random_section_name = '.Tram'#generate_random_string()
    pe.sections[last_section_index].Name = random_section_name.encode("utf-8")[:8].ljust(8, b"\x00")
    
    section_table_offset = pe.DOS_HEADER.e_lfanew + 0x18 + pe.FILE_HEADER.SizeOfOptionalHeader
    section_entry_offset = section_table_offset + last_section_index * 0x28
    data[section_entry_offset: section_entry_offset + 8] = random_section_name.encode("utf-8")[:8].ljust(8, b"\x00")

    for section_index, section in enumerate(pe.sections):
        section_name = section.Name.decode().strip('\x00')
        
        if section_name == '.new':  
            last_section_index = section_index
            #print(last_section_index, section_name)
            random_section_name = '.text'
            pe.sections[last_section_index].Name = '.text'.encode("utf-8")[:8].ljust(8, b"\x00")
            break 
    
    # Update the section header in the PE header
    section_table_offset = pe.DOS_HEADER.e_lfanew + 0x18 + pe.FILE_HEADER.SizeOfOptionalHeader
    section_entry_offset = section_table_offset + last_section_index * 0x28
    data[section_entry_offset: section_entry_offset + 8] = random_section_name.encode("utf-8")[:8].ljust(8, b"\x00")
    

    return bytes(data)


def list_files_by_size(directory):
    try:
        # Get list of files in the directory along with their sizes
        files = [(file, os.path.getsize(os.path.join(directory, file))) for file in os.listdir(directory) if os.path.isfile(os.path.join(directory, file))]
        
        # Sort the list of files by their size
        sorted_files = sorted(files, key=lambda x: x[1])
        
        return [file for file, size in sorted_files]
        
    except Exception as e:
        print(f"Error: {e}")

# Test code
if __name__ == "__main__":
    #src_pefile = "../sample/hello_32.exe"
    #dst_pefile = "../sample/hello_32_new.exe"
    
    input_dir = '../sample/input_sample/'
    #sample_dir = list_files_by_size(sys.argv[1])
    sample_dir = list_files_by_size(input_dir)
    #rint(sample_dir)
    
    for sample in sample_dir:
        #try:
        print(sample)

        if '.ipynb' in sample or 'section_move' in sample:
            continue

        src_pefile = input_dir+sample
        dst_pefile = '../sample/section_move_sample/'+sample.replace('.exe','_new.exe')
        dst_pefile = '../sample/section_move_sample/'+sample.replace('.dll','_new.dll')

        dst_section_name = ".new"
        reloc_section_name = ".reloc"

        data = bytearray(open(src_pefile, "rb").read())
        pe = pefile.PE(data=data)

        all_in_executable, parsed_tables = check_import_tables_in_executable_section(pe)

        cloned_data, src_section_name, bitness = clone_section(data, dst_section_name)

        # Reload the PE structure from the cloned data to get the updated section
        cloned_pe = pefile.PE(data=cloned_data)

        # Get the VA of the first and last executable section
        original_section_va = None
        new_section_va = None

        for section in cloned_pe.sections:
            if section.Characteristics & 0x20000000:  # Check if the section has execute permissions
                if original_section_va is None:
                    original_section_va = section.VirtualAddress
                new_section_va = section.VirtualAddress

        print(f"Original: {hex(original_section_va)}, Cloned: {hex(new_section_va)}")
        if all_in_executable is True and original_section_va is not None and new_section_va is not None:
            # calculate the offset difference
            offset_diff = new_section_va - original_section_va

            # adjust the IMPORT TABLE and IMPORT ADDRESS TABLE entries in the DATA_DIRECTORY
            cloned_pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']].VirtualAddress += offset_diff
            cloned_pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IAT']].VirtualAddress += offset_diff

            # Saved the modified PE file
            cloned_data = bytearray(cloned_pe.write())

            # Adjust parsed_tables entries with the offset difference
            parsed_tables = adjust_parsed_tables(parsed_tables, offset_diff)

            # print("\nParsed Import Table Entries after modification:")
            # for dll_name, entry in parsed_tables.import_table.items():
            #     print(f"DLL Name: {dll_name}")
            #     print(f"    OriginalFirstThunk: {hex(entry.OriginalFirstThunk)}")
            #     print(f"    Name: {hex(entry.Name)}")
            #     print(f"    FirstThunk: {hex(entry.FirstThunk)}")

            # print("\nParsed Import Address Table Entries after modification:")
            # for offset, entry in parsed_tables.import_address_table.items():
            #     print(f"Offset: {hex(offset)}")
            #     print(f"    Entry Data: {entry.entry_data.hex()}")

            # print("\nParsed Import Name Table (INT) Entries after modification:")
            # for offset, entry in parsed_tables.import_name_table.items():
            #     print(f"Offset: {hex(offset)}")
            #     print(f"    Entry Data: {entry.entry_data.hex()}")

            # Apply the changes to the binary data
            cloned_data = update_pe_with_parsed_tables(cloned_data, cloned_pe, parsed_tables)

        print("bitness : ",bitness,type(bitness))

        if bitness == str(64):
            print("not suopport 64bit binary")
            continue

        modified_data = modify_reloc_section(cloned_data, src_section_name, dst_section_name)
        patched_data = insert_trampoline_code(modified_data, src_section_name, dst_section_name)

        # Fetch disassembled instructions for the destination section
        instructions = get_disassembled_instructions(patched_data, dst_section_name)
        adjusted_data = adjust_instruction_offsets(patched_data, src_section_name, dst_section_name, instructions)

        # Fetch disassembled instructions for the destination section
        instructions = get_disassembled_instructions(adjusted_data, dst_section_name)
        adjusted64_data = adjust_rip_relative_offsets(adjusted_data, src_section_name, dst_section_name, instructions)

        adjusted64_data = rename_new_section(adjusted64_data, src_section_name)
        #open(output_file, "wb").write(new_data)

        open(dst_pefile, "wb").write(adjusted64_data)
            
#         except pefile.PEFormatError:
#             continue
            
#         except TypeError:
#             continue
            
#         except IndexError:
#             continue
            
#         except UnboundLocalError:
#             continue