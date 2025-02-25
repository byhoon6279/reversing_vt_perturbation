# Copyright (c) 2021, Mahmood Sharif, Keane Lucas, Michael K. Reiter, Lujo Bauer, and Saurabh Shintre
# This file is code used in Malware Makeover

"""
A collection of tools that can be useful when
running randomization.
"""
import func

def reanalyze_functions(functions, levels):
  """
  Reanalyze the functions to re-run the randomization
  """
  # reset instruction and function's states
  for a, f in functions.items():
    if f.level==-1:
      continue
    # re-init functions that were reordered
    if hasattr(f, 'code'):
      code = f.code
      #was_reordered = [ins_a!=f.code[ins_a].addr for ins_a in f.code]
      was_reordered = [ins_a != f.code.get(ins_a, None).addr for ins_a in f.code if ins_a in f.code]

      if any(was_reordered):
#        code2 = dict([(ins.addr, ins) for ins in code.values()])
        code2 = {ins.addr: ins for ins in code.values()}

        f2 = func.Function(f.addr, code2, f.blocks, \
                           f.code_refs_to, f.code_refs_from)
        #assert(len(f2.blocks)==len(f.blocks))
        #assert(len(f2.instrs)==len(f.instrs))
        f2.name = f.name
        f2.exported = f.exported
        f2.ftype = f.ftype
        f2.level = f.level
        functions[a] = f2
    # update calls/rets/...
    for ref, func_ea in f.code_refs_to:
      try:
        # re-init the data structures
        f2 = functions[func_ea]
        f2.code[ref].USE = set()
        f2.code[ref].DEF = set()
        f2.code[ref].implicit = set()
        f2.code[ref].updated = False
      except KeyError as e:
        pass
    for ins in [x for x in f.instrs if x.mnem == "call"]:
      ins.can_change = set()
      ins.USE = set()
      ins.DEF = set()
      ins.implicit = set()
    for ins in [x for x in f.instrs if x.f_exit]:
      ins.USE = set()
      ins.implicit = set()
    # reset data-structures (mainly of functions that weren't reordered)
    for ins in f.instrs:
      ins.reset_changed()
      ins.apply_changes()
      if ins.updated:
        ins.updated = False
    f.arg_regs = set()
    f.ret_regs = set()
    f.pre_regs = set()
    f.ret_regs = set()
    f.reg_pairs = []
  # run function-level analysis
  func.analyze_functions(functions, levels)


def patch(pe_file, disp_state, diffs):
    """
    Patch the PE file according to the provided diffs (apply the diffs).
    """
    base = pe_file.OPTIONAL_HEADER.ImageBase

    # ✅ PE 섹션 정보 가져오기
    valid_sections = []
    for sec in pe_file.sections:
        sec_start = base + sec.VirtualAddress
        sec_end = sec_start + sec.SizeOfRawData  # ✅ VirtualSize 대신 SizeOfRawData 사용
        valid_sections.append((sec_start, sec_end))

    for ea, orig, new in diffs:
        print(f"Patching address: {hex(ea)} (base: {hex(base)})")  # ✅ 디버깅용 출력

        # (1) ✅ 주소가 올바른 섹션에 속해 있는지 확인
        if not any(sec_start <= ea < sec_end for sec_start, sec_end in valid_sections):
            print(f"❌ Address {hex(ea)} is outside valid sections, skipping...")
            continue

        # (2) ✅ 현재 바이트 읽기 (RVA 변환 후 PE 파일에서 가져오기)
        offset = pe_file.get_offset_from_rva(ea - base)  # ✅ RVA를 실제 파일 오프셋으로 변환
        if offset is None:
            print(f"⚠️  Invalid RVA at {hex(ea)}, skipping...")
            continue

        curr = pe_file.get_data(offset, 1)  # ✅ 오프셋을 사용하여 데이터 가져오기
        if not curr:
            print(f"⚠️  Failed to read memory at {hex(ea)} - Possibly outside mapped sections")
            continue

        if isinstance(curr, bytes) and len(curr) == 1:
            curr = curr[0]

        if isinstance(orig, bytes) and len(orig) == 1:
            orig = orig[0]

        if orig is not None and curr != orig:
            print(f"⚠️  Mismatch at {hex(ea)} - expected {orig}, found {curr}, skipping...")
            continue  # 원래 값과 다르면 패치하지 않음

        # (3) ✅ `new` 값이 올바른 타입인지 변환
        if isinstance(new, str):
            try:
                new = new.encode('latin1')[0]  # `latin1`을 사용해 1바이트 문자열을 변환
            except Exception as e:
                print(f"❌ Failed to convert 'new' to bytes at {hex(ea)}: {e}")
                continue

        # (4) ✅ 바이트 수정 적용
        try:
            if (disp_state is None) or (ea < disp_state.ropf_start):  # non-displaced instruction
                if ea < base:
                    pe_file.set_bytes_at_offset(offset, bytes([new]))  # ✅ RVA에서 변환한 오프셋 사용
                else:
                    pe_file.set_bytes_at_rva(ea - base, bytes([new]))
                print(f"✅ Successfully patched {hex(ea)}")
        except Exception as e:
            print(f"❌ Failed to set bytes at {hex(ea)}: {e}")
