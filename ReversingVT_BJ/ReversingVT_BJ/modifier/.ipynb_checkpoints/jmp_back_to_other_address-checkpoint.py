from capstone import Cs, CS_ARCH_X86, CS_MODE_32
from add_section import * 
from iced_x86 import *
from overlay_append import *
from pwn import *
import lief

def btoi(data: bytes) -> int:
    return int.from_bytes(data, byteorder="little")

def itob4(data: int) -> bytes:
    return data.to_bytes(4, byteorder="little")

def itob2(data: int) -> bytes:
    return data.to_bytes(2, byteorder="little")

def get_overlay_address(data: bytearray) -> int:
    pe_header_offset = btoi(data[0x3C:0x40])
    if data[pe_header_offset : pe_header_offset + 4] != b"PE\x00\x00":
        raise ValueError("Invalid PE header offset")

    section_header_start_offset = pe_header_offset + 0xf8
    total_number_of_sections = btoi(data[pe_header_offset + 0x6 : pe_header_offset + 0x8])

    print(f"⚠️ get_overlay_address [DEBUG] PE 헤더에서 읽은 섹션 개수: {total_number_of_sections}")

    highest_PointerToRawData = 0 
    highest_SizeOfRawData = 0

    for i in range(total_number_of_sections):
        cur_section_header = section_header_start_offset + i * 0x28  # 섹션 헤더 크기
        cur_SizeOfRawData = btoi(data[cur_section_header + 0x10 : cur_section_header + 0x14])
        cur_PointerToRawData = btoi(data[cur_section_header + 0x14 : cur_section_header + 0x18])

        if cur_SizeOfRawData + cur_PointerToRawData > len(data):
            print(f"⚠️ get_overlay_address [WARNING] 섹션 {i}의 Raw Data가 파일 크기보다 큼 (무시됨)")
            continue
        
        if cur_SizeOfRawData + cur_PointerToRawData > highest_PointerToRawData + highest_SizeOfRawData:
            highest_PointerToRawData = cur_PointerToRawData
            highest_SizeOfRawData = cur_SizeOfRawData
    
    if len(data) > highest_PointerToRawData + highest_SizeOfRawData:
        overlay_address = highest_PointerToRawData + highest_SizeOfRawData
        print(f"⚠️ get_overlay_address [DEBUG] 계산된 Overlay 주소: {hex(overlay_address)}")
        return overlay_address

    return None

def search_section_header_by_name(data: bytes, section_name: bytes) -> int:
    pe_header_offset = btoi(data[0x3C:0x40])
    if data[pe_header_offset : pe_header_offset + 4] != b"PE\x00\x00":
        raise ValueError("Invalid PE header offset")

    section_header_start_offset = pe_header_offset + 0xf8
    total_number_of_sections = btoi(data[pe_header_offset + 0x6 : pe_header_offset + 0x8])

    section_header_size = 0x28
    for i in range(total_number_of_sections):
        cur_section_header = section_header_start_offset + i * section_header_size
        cur_section_name = bytes(data[cur_section_header : cur_section_header + 0x8])

        if cur_section_name.replace(b'\x00', b'') == section_name:
            return cur_section_header
    
    return 0

def make_assemble_jmp(jmp_target):
    asm_bytes = b"\x68" + itob4(jmp_target) + b"\xc3"
    return asm_bytes

def make_assemble_call(call_target):
    asm_bytes = b"\x57" + b"\x68" + itob4(call_target) + b"\x5f" + b'\xff\xd7' + b'\x5f'
    return asm_bytes

def manually_add_section(data: bytearray, section_name: str):
    pe_header_offset = btoi(data[0x3C:0x40])
    section_table_offset = pe_header_offset + 0xf8
    num_sections = btoi(data[pe_header_offset + 6: pe_header_offset + 8])

    # 🔥 새 섹션 추가할 위치 계산
    new_section_offset = section_table_offset + num_sections * 0x28
    if new_section_offset + 0x28 > len(data):
        raise ValueError("[-] 새로운 섹션을 추가할 공간이 부족함.")

    # ✅ 새 섹션 헤더 작성
    data[new_section_offset : new_section_offset + 8] = section_name.encode().ljust(8, b"\x00")  # 섹션 이름

    # 🔥 섹션 기본 설정 (기본 크기 0x1000)
    data[new_section_offset + 0x8 : new_section_offset + 0x10] = itob4(0x1000)  # VirtualSize
    data[new_section_offset + 0x10 : new_section_offset + 0x14] = itob4(0x1000)  # SizeOfRawData
    data[new_section_offset + 0x14 : new_section_offset + 0x18] = itob4(len(data))  # PointerToRawData (파일 끝에 추가)
    data[new_section_offset + 0x24 : new_section_offset + 0x28] = itob4(0x60000020)  # Characteristics (RWX 권한)

    # ✅ PE 헤더의 섹션 개수 증가
    data[pe_header_offset + 6 : pe_header_offset + 8] = itob2(num_sections + 1)
    print(f"✅ [DEBUG] .ccc 섹션 추가 완료! 새 섹션 개수: {num_sections + 1}")

    return data

def fix_reloc_section(data: bytearray):
    pe_header_offset = btoi(data[0x3C:0x40])
    num_sections = btoi(data[pe_header_offset + 6: pe_header_offset + 8])
    section_table_offset = pe_header_offset + 0xf8

    for i in range(num_sections):
        section_offset = section_table_offset + (i * 0x28)
        section_name = data[section_offset : section_offset + 8].rstrip(b"\x00").decode(errors="ignore")

        if section_name == ".reloc":
            size_of_raw_data = btoi(data[section_offset + 0x10 : section_offset + 0x14])
            pointer_to_raw_data = btoi(data[section_offset + 0x14 : section_offset + 0x18])

            # 🔥 .reloc 섹션 크기가 비정상적으로 크면 강제 조정
            if size_of_raw_data > 0x10000:  # 64KB 이상이면 비정상
                print(f"⚠️ .reloc 섹션 크기 비정상 ({size_of_raw_data:#x}) → 0x1000로 조정")
                data[section_offset + 0x10 : section_offset + 0x14] = itob4(0x1000)

    return data

def fix_pe_data_directory(data: bytearray):
    pe_header_offset = btoi(data[0x3C:0x40])
    optional_header_offset = pe_header_offset + 0x18

    # Import Table, Reloc Table 위치 확인
    import_rva = btoi(data[optional_header_offset + 0x80 : optional_header_offset + 0x84])
    reloc_rva = btoi(data[optional_header_offset + 0xa0 : optional_header_offset + 0xa4])

    if import_rva == 0 or reloc_rva == 0:
        print("⚠️ Import Table 또는 Reloc Table의 RVA가 0으로 설정됨 → 수정 필요")

        # 예제: Import Table을 .data 섹션 위치로 이동
        data[optional_header_offset + 0x80 : optional_header_offset + 0x84] = itob4(0x400000 + 0x2000)
        data[optional_header_offset + 0xa0 : optional_header_offset + 0xa4] = itob4(0x400000 + 0x3000)

    return data




def jmp_back_to_other_address(data: bytes, hook_target_VA: int, overlay_address: int) -> bytes:
    data = bytearray(data)

    pe_header_offset = btoi(data[0x3C:0x40])
    
    if data[pe_header_offset : pe_header_offset + 4] != b"PE\x00\x00":
        raise ValueError("Invalid PE header offset")

    # 🔥 PE 섹션 개수 확인
    section_header_start_offset = pe_header_offset + 0xf8
    total_number_of_sections = btoi(data[pe_header_offset + 0x6 : pe_header_offset + 0x8])
    lief_parsed = lief.parse(bytes(data))
    
    if lief_parsed is None:
        raise ValueError("[-] lief가 PE 파일을 정상적으로 읽지 못함 (파일이 손상되었거나 압축됨)")

    lief_section_count = len(lief_parsed.sections)

    print(f"⚠️ jmp_back_to_other_address [DEBUG] PE 헤더에서 읽은 섹션 개수: {total_number_of_sections}")
    print(f"⚠️ jmp_back_to_other_address [DEBUG] lief에서 읽은 섹션 개수: {lief_section_count}")

    # ✅ 값 조정
    if abs(total_number_of_sections - lief_section_count) > 2:
        print("⚠️ jmp_back_to_other_address [WARNING] lief와 PE 헤더 섹션 개수 차이가 큼 → PE 헤더 값을 사용")
        total_number_of_sections = lief_section_count

    print(f"⚠️ jmp_back_to_other_address [DEBUG] 최종 PE 섹션 개수: {total_number_of_sections}")

    # 🔥 기존 .ccc 섹션 확인
    hook_section_header = search_section_header_by_name(data, b".ccc")

    if hook_section_header == 0:
        print("[+] .ccc 섹션 없음 → 새로 추가")
        if total_number_of_sections >= 50:
            raise ValueError("PE 섹션 개수가 너무 많아 .ccc 섹션 추가 중단")

        # 🔥 우선 `lief.add_section()` 시도
        try:
            data = add_section(data, ".ccc", b"\x00" * 0x1000, PERM.READ | PERM.EXEC)
            lief_parsed_after = lief.parse(bytes(data))
            if lief_parsed_after:
                print(f"🔥 jmp_back_to_other_address [DEBUG] 섹션 추가 후 PE 섹션 목록: {[sec.name for sec in lief_parsed_after.sections]}")
        except Exception as e:
            print(f"⚠️ lief.add_section() 실패: {str(e)}")

        # 🔥 `lief.add_section()`이 실패했거나 `.ccc` 섹션이 안 보이면 `manually_add_section()` 실행
        hook_section_header = search_section_header_by_name(data, b".ccc")
        if hook_section_header == 0:
            print("[+] lief로 .ccc 섹션 추가 실패 → 직접 PE 헤더 수정")
            data = manually_add_section(data, ".ccc")
            data = fix_reloc_section(data)
            data = fix_pe_data_directory(data)

        # ✅ 다시 `.ccc` 위치 확인
        hook_section_header = search_section_header_by_name(data, b".ccc")
        if hook_section_header == 0:
            raise ValueError("[-] .ccc 섹션 추가 실패")
        
        print(f"[DEBUG] .ccc 추가 후 PE 섹션 개수: {total_number_of_sections + 1}")
    else:
        print("[+] 기존 .ccc 섹션 찾음 → 추가 안 함")

    return data


if __name__ == '__main__':
    data = bytearray(open("test/putty.exe", "rb").read())
    data = overlay_append_dummy(data, itob4(0x40105c))
    overlay_addr = 0x115120

    print(f"target overlay = {hex(overlay_addr)}")
    new_data = jmp_back_to_other_address(data, 0x401000, overlay_addr)
    open("test/putty_new.exe", "wb").write(new_data)