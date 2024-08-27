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


def get_pe_sections(pe) -> list:
    sections = []
    for section in pe.sections:
        sections.append(SectionInfo(
            name=section.Name.decode().strip('\x00'),
            virtual_address=section.VirtualAddress,
            virtual_size=section.Misc_VirtualSize,
            raw_data_offset=section.PointerToRawData,
            raw_data_size=section.SizeOfRawData,
            characteristics=section.Characteristics
        ))
    return sections


def parse_import_tables(pe) -> ParsedImportTables:
    sections = get_pe_sections(pe)
    parsed_tables = ParsedImportTables()

    import_table_rva = None
    import_address_table_rva = None

    # Check the IMPORT TABLE RVA and IAT RVA
    directory_entry_idt = pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']
    directory_entry_iat = pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IAT']

    if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > directory_entry_idt and \
        pe.OPTIONAL_HEADER.DATA_DIRECTORY[directory_entry_idt].Size > 0:
            import_table_rva = pe.OPTIONAL_HEADER.DATA_DIRECTORY[directory_entry_idt].VirtualAddress
            for section in sections:
                if section.section_start <= import_table_rva < section.section_end:
                    parsed_tables.import_table_section_name = section.name
                    logging.info(f'IDT found at RVA: {hex(import_table_rva)} - Section: {section.name}')
    else:
        logging.warning('IMPORT_TABLE Data Directory entry NOT found.')
    
    if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > directory_entry_iat and \
        pe.OPTIONAL_HEADER.DATA_DIRECTORY[directory_entry_iat].Size > 0:
        import_address_table_rva = pe.OPTIONAL_HEADER.DATA_DIRECTORY[directory_entry_iat].VirtualAddress
        for section in sections:
            if section.section_start <= import_address_table_rva < section.section_end:
                parsed_tables.import_address_table_section_name = section.name
                logging.info(f'IAT found at RVA: {hex(import_address_table_rva)} - Section: {section.name}')
        
    else:
        logging.warning('IMPORT_ADDRESS_TABLE Data Directory entry NOT found.')
    
    if not import_table_rva:
        return parsed_tables

    try:
        # Parse the IMPORT DIRECTORY TABLEs
        while True:
            descriptor_data = pe.get_data(import_table_rva, 20)
            logging.debug(f'Descriptor Data: {hex(import_table_rva)}, {descriptor_data}')
            if all(b == 0 for b in descriptor_data):
                logging.debug('End of IMPORT DIRECTORY TABLE entries.')
                break
            
            descriptor = pefile.Structure(pe.__IMAGE_IMPORT_DESCRIPTOR_format__, file_offset=import_table_rva)
            descriptor.__unpack__(descriptor_data)

            logging.debug(f'Descriptor: {descriptor}')

            dll_name_rva = descriptor.Name
            dll_name = pe.get_string_at_rva(dll_name_rva)
            logging.debug(f'Processing DLL rva: {hex(dll_name_rva)}, name: {dll_name}')

            parsed_tables.import_table[dll_name] = ImportTableEntry(
                OriginalFirstThunk=descriptor.OriginalFirstThunk,
                TimeDateStamp=descriptor.TimeDateStamp,
                ForwarderChain=descriptor.ForwarderChain,
                Name=descriptor.Name,
                FirstThunk=descriptor.FirstThunk
            )

            # Parse the Original First Thunk for Import Name Table (INT)
            if descriptor.OriginalFirstThunk:
                int_rva = descriptor.OriginalFirstThunk
                logging.debug(f'OriginalFirstThunk: {hex(descriptor.OriginalFirstThunk)}')
                while True:
                    int_entry = int.from_bytes(pe.get_data(int_rva, 4), byteorder='little')
                    if int_entry == 0:
                        break

                    parsed_tables.import_name_table[int_rva] = ImportNameTableEntry(
                        offset=int_rva,
                        entry_data=int_entry.to_bytes(4, byteorder='little')
                    )
                    logging.debug(f'Processing INT rva: {hex(int_rva)}, data: {hex(int_entry)}')
                    int_rva += 4
            
            # Parse the FirstThunk for Import Address Table (IAT)
            if descriptor.FirstThunk:
                iat_rva = descriptor.FirstThunk
                logging.debug(f'FirstThunk: {hex(descriptor.FirstThunk)}')
                while True:
                    iat_entry_size = 8 if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64'] else 4
                    iat_entry = pe.get_data(iat_rva, iat_entry_size)
                    if int.from_bytes(iat_entry, byteorder='little') == 0:
                        break
                    
                    parsed_tables.import_address_table[iat_rva] = ImportAddressTableEntry(
                        offset=iat_rva,
                        entry_data=iat_entry
                    )
                    logging.debug(f'Processing IAT rva: {hex(iat_rva)}, offset: {iat_entry}')
                    iat_rva += iat_entry_size
            import_table_rva += 20

    except pefile.PEFormatError as e:
        logging.error(f'PE format error encountered: {str(e)}')
        return parsed_tables
    
    return parsed_tables


def update_parsed_tables(cloned_data, cloned_pe, parsed_tables, original_name, rva_diff):
    cloned_data = bytearray(cloned_data)
    import_table_rva = cloned_pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']].VirtualAddress
    
    # Adjust Import Table Entries (IDT)
    if parsed_tables.import_table_section_name == original_name:
        for i, (dll_name, entry) in enumerate(parsed_tables.import_table.items()):
            descriptor_rva = import_table_rva + i * 20
            if entry.OriginalFirstThunk != 0:
                entry.OriginalFirstThunk += rva_diff
                cloned_data[descriptor_rva:descriptor_rva + 4] = struct.pack('<I', entry.OriginalFirstThunk)
                logging.debug(f"Adjusted OriginalFirstThunk RVA for {dll_name}: {hex(entry.OriginalFirstThunk)}")
            if entry.Name != 0:
                entry.Name += rva_diff
                cloned_data[descriptor_rva + 12:descriptor_rva + 16] = struct.pack('<I', entry.Name)
                logging.debug(f"Adjusted Name RVA for {dll_name}: {hex(entry.Name)}")
            if entry.FirstThunk != 0: # IAT가 코드 섹션에 포함되어 있는지 더블체크?
                entry.FirstThunk += rva_diff
                cloned_data[descriptor_rva + 16:descriptor_rva + 20] = struct.pack('<I', entry.FirstThunk)
                logging.debug(f"Adjusted FirstThunk RVA for {dll_name}: {hex(entry.FirstThunk)}")
    
        # Adjust Import Name Table Entries (INT)
        adjusted_import_name_table_entries = {}
        ordinal_indices = set()
        current_index = 0
        for rva, entry in parsed_tables.import_name_table.items():
            int_rva = rva + rva_diff
            entry_data_value = int.from_bytes(entry.entry_data, byteorder='little')
            if is_ordinal(entry_data_value):
                ordinal_indices.add(current_index)
                logging.debug(f"INT entry at offset {hex(rva)} is an Ordinal: {hex(entry_data_value)}")
                adjusted_import_name_table_entries[int_rva] = ImportNameTableEntry(
                    offset=int_rva,
                    entry_data=entry_data_value.to_bytes(4, byteorder='little')
                )
            else:
                entry_data_value += rva_diff
                adjusted_import_name_table_entries[int_rva] = ImportNameTableEntry(
                    offset=int_rva,
                    entry_data=entry_data_value.to_bytes(4, byteorder='little')
                )
            cloned_data[int_rva:int_rva + 4] = entry_data_value.to_bytes(4, byteorder='little')
            logging.debug(f"Adjusted INT entry at new offset {hex(int_rva)}: {hex(entry_data_value)}")
            
            current_index += 1
        
        parsed_tables.import_name_table.clear()
        parsed_tables.import_name_table.update(adjusted_import_name_table_entries)

    # Adjust Import Address Table (IAT) Entries
    if parsed_tables.import_address_table_section_name == original_name:
        adjusted_import_address_table_entries = {}
        current_index = 0
        for rva, entry in parsed_tables.import_address_table.items():
            iat_rva = rva + rva_diff
            if current_index in ordinal_indices:
                logging.debug(f"IAT entry at offset {hex(rva)} corresponds to an Ordinal, not updating.")
                adjusted_import_address_table_entries[iat_rva] = ImportAddressTableEntry(
                    offset=iat_rva,
                    entry_data=entry_data_value.to_bytes(4, byteorder='little')
                )
            else:
                entry_data_value = int.from_bytes(entry.entry_data, byteorder='little') + rva_diff
                adjusted_import_address_table_entries[iat_rva] = ImportAddressTableEntry(
                    offset=iat_rva,
                    entry_data=entry_data_value.to_bytes(4, byteorder='little')
                )
            cloned_data[iat_rva:iat_rva + 4] = entry_data_value.to_bytes(4, byteorder='little')
            current_index += 1  
        parsed_tables.import_address_table.clear()
        parsed_tables.import_address_table.update(adjusted_import_address_table_entries)

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


def find_section_by_name(pe, section_name):
    for section in pe.sections:
        decoded_name = section.Name.decode('utf-8').strip('\x00').strip()
        if decoded_name == section_name.strip():
            return section
    logging.debug(f"Section {section_name} not found in PE sections.")
    return None


# 섹션 권한 결정 함수
def determine_section_permissions(section):
    return (PERM.EXEC if section.characteristics & 0x20000000 else 0) | \
           (PERM.READ if section.characteristics & 0x40000000 else 0) | \
           (PERM.WRITE if section.characteristics & 0x80000000 else 0)

# fix this: offset -> rva
def update_data_directory(restored_data, pe, padding_start, size):
    data_directory_offset = (
        pe.DOS_HEADER.e_lfanew
        + 0x18  # PE Signature and File Header
        + pe.FILE_HEADER.SizeOfOptionalHeader   # Optional Header Size
        - 0x80  # Adjusting to the start of Data Directory
        + pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT'] * 8  # Offset within Data Directory array
    )
    restored_data[data_directory_offset:data_directory_offset + 4] = struct.pack("<I", padding_start)
    restored_data[data_directory_offset + 4:data_directory_offset + 8] = struct.pack("<I", size)

# fix this: offset -> rva
def restore_bound_import_directory(data: bytes, bound_import_data: bytes) -> bytes:
    pe = pefile.PE(data=data)
    section_table_offset = pe.DOS_HEADER.e_lfanew + 0x18 + pe.FILE_HEADER.SizeOfOptionalHeader
    section_count = pe.FILE_HEADER.NumberOfSections
    last_section_offset = section_table_offset + section_count * 0x28
    padding_start = last_section_offset
    padding_end = (padding_start + pe.OPTIONAL_HEADER.FileAlignment - 1) & ~(pe.OPTIONAL_HEADER.FileAlignment - 1)

    if len(bound_import_data) > (padding_end - padding_start):
        raise ValueError("Not enough space in padding area to restore BOUND IMPORT DIRECTORY.")
    
    restored_data = bytearray(data)
    for i in range(len(bound_import_data)):
        restored_data[padding_start + i] = bound_import_data[i]

    logging.debug(f"padding start-end: {padding_start} - {padding_end}")
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
    logging.debug(f"Restored Bound Import Directory Data at new offset ({hex(padding_start)}): {written_data.hex()}")

    return bytes(restored_data)


def backup_bound_import_directory(pe):
    global bound_import_rva, bound_import_size, bound_import_data

    directory_entry_bound_import = pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT']

    if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > directory_entry_bound_import:
        bound_import_rva = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT']].VirtualAddress
        bound_import_size= pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT']].Size

        if bound_import_rva and bound_import_size:
            bound_import_data = pe.get_memory_mapped_image()[bound_import_rva:bound_import_rva + bound_import_size]
            logging.debug(f"Bound Import Directory: {hex(bound_import_rva)} {hex(bound_import_size)} {bound_import_data}")
    else:
        logging.warn(f"BOUND_IMPORT data directory NOT found")
        bound_import_rva = 0
        bound_import_size = 0
        bound_import_data = bytes()


def verify_bound_import_directory(cloned_section):
    global bound_import_rva, bound_import_size, bound_import_data
    pe = pefile.PE(data=cloned_section)
    directory_entry_bound_import = pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT']

    if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) > directory_entry_bound_import:
        bound_import_rva_after = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT']].VirtualAddress
        bound_import_size_after = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT']].Size

        logging.debug(f"After adding section:\nBound Import Directory RVA: {hex(bound_import_rva_after)}, Size: {bound_import_size_after}")
        
        if bound_import_rva != bound_import_rva_after or bound_import_size != bound_import_size_after:
            bound_import_data_after = pe.get_memory_mapped_image()[bound_import_rva_after:bound_import_rva_after + bound_import_size_after]
            logging.debug(f"After adding section2:\nBound Import Directory Data: {bound_import_data_after.hex()}")
            
            if bound_import_data != bound_import_data_after:
                if bound_import_data:
                    return restore_bound_import_directory(cloned_section, bound_import_data)
    else:
        logging.warn(f"BOUND_IMPORT data directory entry not found in the modified PE.")
    
    return cloned_section


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
                logging.info(f"No valid instruction found at offset {offset}, trying next byte...")
                offset += 1
                continue
                
            yield instruction
            offset += instruction.size
                
        except capstone.CsError as e:
            logging.info(f"Capstone decoding error at offset {hex(va + offset)}: {str(e)}")
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


def clone_section(data: bytes) -> bytes:
    pe = pefile.PE(data=data)
    cloned_data = data [:]

    backup_bound_import_directory(pe)

    executable_sections = [ section for section in get_pe_sections(pe) if section.is_executable ]
    if not executable_sections:
        raise ValueError("No valid section found for cloning")
    
    original_sections_info = []
    cloned_sections_info = []
    clone_index = 0
    for section in executable_sections:
        logging.info(f"Cloning section: {section.name}")

        cloned_section_name = f".clone{clone_index}"
        clone_index += 1

        source_data = cloned_data[section.raw_data_offset:section.raw_data_offset + section.raw_data_size]
        source_perms = determine_section_permissions(section)
        cloned_data = add_section(cloned_data, cloned_section_name, source_data, source_perms)
        cloned_data = verify_bound_import_directory(bytearray(cloned_data))

        original_sections_info.append(section.name)
        cloned_sections_info.append(cloned_section_name)

    return cloned_data, original_sections_info, cloned_sections_info


def check_bitness(pe):
    try:
        if pe.OPTIONAL_HEADER.Magic == 0x108:
            return str(32)
        elif pe.OPTIONAL_HEADER.Magic == 0x20B:
            return str(64)
    except AttributeError:
        return "Not a valid PE file"


def calculate_rva_diff(pe, src_section_name, dst_section_name):
    src_section = find_section_by_name(pe, src_section_name)
    dst_section = find_section_by_name(pe, dst_section_name)

    if not src_section or not dst_section:
        raise ValueError(f"One of the sections {src_section_name}, {dst_section_name} not found")

    rva_diff = dst_section.VirtualAddress - src_section.VirtualAddress
    return rva_diff


def clear_original_sections(data:bytes, original_sections: List[str]) -> bytes:
    pe = pefile.PE(data=data)
    cloned_data = bytearray(data)

    for section_name in original_sections:
        section = find_section_by_name(pe, section_name)
        if section:
            nop_area = bytes([0x90] * section.SizeOfRawData)
            cloned_data[section.PointerToRawData:section.PointerToRawData + section.SizeOfRawData] = nop_area
            logging.info(f"Cleared section {section_name} with NOPs.")
    
    return cloned_data

def insert_trampoline_code(data: bytes, src_section_name:str, dst_section_name: str) -> bytes:
    pe = pefile.PE(data=data)
    modified_data = bytearray(data)

    # Locate the code section
    entry_point_va = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    src_section = find_section_by_name(pe, src_section_name)
    dst_section = find_section_by_name(pe, dst_section_name)

    if not src_section or not dst_section:
        raise ValueError(f"Section {src_section_name} or {dst_section_name} not found")

    if not (src_section.VirtualAddress <= entry_point_va < src_section.VirtualAddress + src_section.Misc_VirtualSize):
        logging.debug(f"Entry point 0x{entry_point_va:x} is not within the source section {src_section_name}")
    
    entrypoint_offset = entry_point_va - src_section.VirtualAddress
    jump_destination_rva = dst_section.VirtualAddress + entrypoint_offset

    # Construct the jump instruction to the new entry point
    # For example, using a direct jump which is 5 bytes in x86 (E9 xx xx xx xx)
    # Calculate the offset for the jump instruction
    offset = jump_destination_rva - (src_section.VirtualAddress + entrypoint_offset + 5)
    jump_instruction = b'\xE9' + offset.to_bytes(4, byteorder='little', signed=True)
    
    # Place the jump instruction at the start of the code section
    entrypoint_raw = src_section.PointerToRawData + entrypoint_offset
    modified_data[entrypoint_raw:entrypoint_raw + 5] = jump_instruction
    logging.info(f"Inserted trampoline jump from {src_section_name} to {dst_section_name} at raw offset 0x{entrypoint_raw:x}.")

    return modified_data


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