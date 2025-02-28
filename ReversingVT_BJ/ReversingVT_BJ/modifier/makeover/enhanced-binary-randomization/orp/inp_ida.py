import idautils
import idaapi
import idc
import ida_auto
import ida_bytes
import ida_pro
import ida_xref
import pefile
import capstone
import pickle
import util
import bbl
import insn
import func
import time
from collections import OrderedDict

__all__ = ["get_functions", "dump_data", "get_code_heads", "code_search", "max_ea", "byte_at", "bytes_at", "seg_start", "seg_end", "get_func_of"]

code_heads = set()

# ✅ Capstone 디스어셈블러 초기화 (x86/x64 지원)
CS_MODE = capstone.CS_MODE_32  # 32비트 모드 설정
md = capstone.Cs(capstone.CS_ARCH_X86, CS_MODE)
md.detail = True  # Capstone 상세 모드 활성화
# Capstone 모드 설정
md32 = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md64 = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

md32.detail = True
md64.detail = True

def get_typed_imports():
    """Queries IDA for functions in the import table that do have a type.
    Returns a set of (func_ea, func_type) tuples."""
    imp_funcs = set()
    for i in range(idaapi.get_import_module_qty()):

        def imp_cb(ea, name, ordn):
            ftype = idc.get_type(ea)
            if ftype:
                imp_funcs.add((ea, ftype))
            return True
        idaapi.enum_import_names(i, imp_cb)
    return imp_funcs

def get_export_list():
    """Returns a set of the exported function addresses."""
    return {ea for i, ordn, ea, name in idautils.Entries()}

def get_func_code_refs_from(func_ea, iaddrs):
    """Returns a set with the code references from this function."""
    code_refs = set()
    for addr in iaddrs:
        ref = idaapi.BADADDR
        for r in idautils.XrefsFrom(addr, ida_xref.XREF_ALL):
            if r.iscode:
                to_func = idaapi.get_func(r.to)
                if not to_func or to_func.start_ea != func_ea:
                    ref = r.to
            else:
                ref = r.to
        if ref != idaapi.BADADDR and idc.print_insn_mnem(addr) in {"call", "jmp"}:
            code_refs.add(ref)
    return code_refs

def get_func_code_refs_to(func_ea):
    """Returns a set with the code references to this function."""
    return {(ref, func.start_ea) for ref in idautils.CodeRefsTo(func_ea, 0) if (func := idaapi.get_func(ref)) is not None}

def get_code_and_blocks(ea):
    """Extracts the control flow graph for the function at the given address."""
    code = {}
    blocks = {}
    ida_blocks = set(idaapi.FlowChart(idaapi.get_func(ea)))
    
    for bb in ida_blocks:
        if bb.start_ea == bb.end_ea:
            continue
        blocks[bb.start_ea] = bbl.BasicBlock(bb.start_ea, bb.end_ea, {})
        for head in idautils.Heads(bb.start_ea, bb.end_ea):
            ibytes = ida_bytes.get_bytes(head, ida_bytes.get_item_end(head) - head)
            code[head] = md.disasm(ibytes, head).__next__()
            blocks[bb.start_ea].instrs.append(code[head])
            next_head = idc.next_head(head, bb.end_ea)
            if ida_bytes.is_flow(ida_bytes.get_full_flags(next_head)):
                code[head].succ.add(next_head)
        for suc_bb in (s for s in bb.succs() if s.start_ea != s.end_ea):
            code[head].succ.add(suc_bb.start_ea)
    
    return code, list(blocks.values())
def get_code_and_blocks(ea):
    """Extracts the control flow graph for the function at the given address."""
    code = {}
    blocks = {}
    ida_blocks = set(idaapi.FlowChart(idaapi.get_func(ea)))

    for bb in ida_blocks:
        if bb.start_ea == bb.end_ea:
            continue

        blocks[bb.start_ea] = bbl.BasicBlock(bb.start_ea, bb.end_ea, {})
        
        for head in idautils.Heads(bb.start_ea, bb.end_ea):
            ibytes = ida_bytes.get_bytes(head, ida_bytes.get_item_end(head) - head)
            if not ibytes:
                continue  # 빈 명령어는 건너뜀
            
            # ✅ Capstone으로 명령어 디코딩
            disasm_list = list(md.disasm(ibytes, head))
            if not disasm_list:
                continue  # Capstone이 디코딩 실패하면 건너뜀
            
            ins = disasm_list[0]
            code[head] = insn.Instruction(head, ins.bytes)  # ✅ 원래 Instruction 클래스 활용
            blocks[bb.start_ea].instrs.append(code[head])

            # ✅ 다음 명령어 주소 설정
            next_head = idc.next_head(head, bb.end_ea)
            if ida_bytes.is_flow(ida_bytes.get_full_flags(next_head)):
                code[head].succ.add(next_head)

        # ✅ 블록 간 제어 흐름 설정
        for suc_bb in (s for s in bb.succs() if s.start_ea != s.end_ea):
            code[head].succ.add(suc_bb.start_ea)

    # ✅ Entry Point 찾기
    for block in blocks.values():
        if block.instrs and block.instrs[0].addr == ea:
            block.instrs[0].f_entry = True
            block.type |= bbl.BasicBlock.ENTRY
            break
    else:
        print(f"❌ [BUG] 함수 {hex(ea)}의 Entry Block을 찾을 수 없음!")

    return code, list(blocks.values())


def functions_iter():
    functions = set()
    exports = get_export_list()

    for func_ea in idautils.Functions():
        if func_ea in functions:
            continue  # 함수가 중복 등록되지 않도록 방지

        functions.add(func_ea)
        code, blocks = get_code_and_blocks(func_ea)
        crefs_to = get_func_code_refs_to(func_ea)
        crefs_from = get_func_code_refs_from(func_ea, code.keys())
        f = func.Function(func_ea, code, blocks, crefs_to, crefs_from)
        f.ftype = idc.get_type(func_ea)
        f.name = idc.get_func_name(func_ea)

        if func_ea in exports:
            f.exported = True

        # Jumps 처리 (Capstone 사용)
        if code:
            ins_addrs = {ins.addr for ins in f.instrs}  # 빠른 조회를 위해 set 사용
            for block in f.blocks:
                for ins in block.instrs:
                    if ins.mnem == "jmp" and ins.bytes:
                        try:
                            # Capstone을 이용해 명령어 분석
                            disasm_engine = md64 if capstone.CS_MODE == capstone.CS_MODE_64 else md32
                            for inst in disasm_engine.disasm(ins.bytes, ins.addr):
                                if inst.mnemonic == "jmp" and inst.operands:
                                    # 점프 대상 주소 정리 (정규 표현식 사용)
                                    match = re.search(r"0x[0-9A-Fa-f]+", inst.op_str)
                                    if match:
                                        jmp_target = int(match.group(0), 16)  # 16진수 변환
                                        if jmp_target not in ins_addrs:
                                            ins.f_exit = True
                                            block.type = bbl.BasicBlock.EXIT
                        except Exception as e:
                            print(f"[ERROR] Failed to disassemble instruction at {hex(ins.addr)}: {e}")

        # ADD/SUB 명령어 처리 (EFLAGS 관련)
        if f.code:
            for block in f.blocks:
                instrs = sorted(block.instrs, key=lambda ins: ins.addr)
                for ins1 in instrs:
                    ins1.irreplaceable = False
                    if ins1.mnem in ("add", "sub"):
                        for ins2 in instrs:
                            if ins2.addr > ins1.addr:
                                if ins2.eflags_r or ins2.mnem in ("adc", "sbb"):
                                    ins1.irreplaceable = True
                                    break
                                if ins2.eflags_w:
                                    ins1.irreplaceable = False
                                    break

        yield f

    # Import 함수 처리
    typed_imports = get_typed_imports()
    for imp_ea, ftype in typed_imports:
        crefs_to = get_func_code_refs_to(imp_ea)
        f = func.Function(imp_ea, None, None, crefs_to, None)
        f.ftype = ftype
        f.level = -1  # Special level for imported functions
        yield f


def get_functions(unused_arg=None):
    """Extracts useful data from the file being processed.
    Returns a dictionary {ea: func.Function} containing all
    functions disassembled by IDA."""

    functions = {}

    for f in functions_iter():
        functions[f.addr] = f

    return functions

def dump_data():
    """Extracts and dumps useful data from the file being processed."""
    dump_out = util.open_dump(idaapi.get_input_file_path(), "wb")
    pickle.dump(get_code_heads(), dump_out)
    for f in get_functions().values():
        pickle.dump(f, dump_out)
    pickle.dump(None, dump_out)
    dump_out.close()

def get_code_heads():
    """Returns a set with all recognized code heads."""
    global code_heads
    if not code_heads:
        for begin, end, name in code_segments_iter():
            code_heads |= {x for x in idautils.Heads(begin, end) if idc.is_code(ida_bytes.get_full_flags(x))}
    return code_heads

def code_segments_iter():
    """Iterates over the possible code sections within an input binary."""
    for seg_start in idautils.Segments():
        seg = idaapi.getseg(seg_start)
        if seg and idaapi.get_segm_class(seg) == "CODE":
            yield seg.start_ea, seg.end_ea, idaapi.get_segm_name(seg)

def byte_at(ea):
    """Returns the byte at the given address."""
    return ida_bytes.get_byte(ea)

def max_ea():
    """Returns the max effective address for this binary."""
    return idaapi.get_inf_structure().max_ea

def bytes_at(ea, num):
    """Returns num of bytes at the given address."""
    return ida_bytes.get_bytes(ea, num)

def seg_start(ea):
    """Returns the start of the segment that ea belongs in."""
    return idaapi.get_segm_start(ea)

def seg_end(ea):
    """Returns the end of the segment that ea belongs in."""
    return idaapi.get_segm_end(ea)

def get_func_of(ea):
    """Return the function that this address belongs to, if any."""
    func = idaapi.get_func(ea)
    return func.start_ea if func else None

def get_input_file_path():
    """Return the name of the currently processed file."""
    return idaapi.get_input_file_path()

if __name__ == "__main__":
    import sys
    sys.setrecursionlimit(40000)
    ida_auto.auto_wait()
    dump_data()
    #time.sleep(10)
    ida_pro.qexit(0)
