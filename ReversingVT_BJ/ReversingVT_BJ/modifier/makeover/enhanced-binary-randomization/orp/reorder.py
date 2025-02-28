#!/usr/bin/env python3

import itertools
import capstone  # ✅ pydasm 대신 Capstone 사용
import pefile
import random
import inp
import disp
import insn
import randtoolkit
from bbl import BasicBlock
from collections import deque
from pygraph.classes.digraph import digraph

# Capstone 엔진 초기화 (x86, 32-bit 모드)
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

# ✅ Capstone으로 변경된 Instruction Type 목록
UNMOVABLE = {
    capstone.x86.X86_GRP_JUMP,
    capstone.x86.X86_GRP_CALL,
    capstone.x86.X86_GRP_RET,
    capstone.x86.X86_GRP_INT,
    capstone.x86.X86_GRP_PRIVILEGE,
}

def build_bb_dependence_dag(bb):
    """기본 블록(BB)의 의존성 그래프를 생성"""
    dependence_graph = digraph()
    reachable_fwd = {}
    reachable_bkwd = {}

    size = len(bb.instrs)
    if size > 5000:
        return build_degenerate_dag(bb)

    for j in range(size):
        dependence_graph.add_node(bb.instrs[j])
        conflict = set()
        for k in reversed(range(j)):
            if conflict_detected(bb.instrs[k], bb.instrs[j]):
                if reachable_fwd.get(k, set()).intersection(conflict):
                    continue
                conflict.add(k)
                dependence_graph.add_edge((bb.instrs[k], bb.instrs[j]))
                reachable_fwd.setdefault(k, set()).add(j)
                reachable_bkwd.setdefault(j, set()).add(k)
                for v in reachable_bkwd.get(k, []):
                    reachable_fwd[v].add(j)
                reachable_bkwd.setdefault(j, set()).update(reachable_bkwd.get(k, []))
    return dependence_graph

def conflict_detected(i1, i2):
    """두 개의 명령어가 충돌하는지 검사"""
    if i1.type in UNMOVABLE or i2.type in UNMOVABLE:
        return True
    if disp._is_displaced(i1) or disp._is_displaced(i2):
        return True
    if not i1.DEF.isdisjoint(i2.USE):
        return True
    if not i1.USE.isdisjoint(i2.DEF):
        return True
    if not i1.DEF.isdisjoint(i2.DEF):
        return True
    return False

def reorder_graph_randomly(dag):
    """랜덤으로 DAG 내부의 명령어 순서를 재배열"""
    if not dag.edges():
        nodes = list(dag.nodes())
        random.shuffle(nodes)
        return nodes

    ordering = []
    edge_srcs, edge_dsts = zip(*dag.edges())
    roots = set(edge_srcs) - set(edge_dsts)
    roots.update(set(dag.nodes()) - set(itertools.chain(*dag.edges())))
    roots = deque(roots)
    random.shuffle(roots)

    while roots:
        n = roots.popleft()
        ordering.append(n)
        for m in dag.node_neighbors[n][:]:
            dag.del_edge((n, m))
            if not dag.node_incidence[m]:
                roots.append(m)
        random.shuffle(roots)
    return ordering

def do_random_reordering(f, pe_file):
    """
    Reorder function f's instructions randomly, while maintaining dependencies.
    Returns:
      - diffs: 변경된 바이트 정보 리스트
      - changed_bytes: 변경된 주소의 set (정수가 아님!)
    """
    diffs = []
    changed_bytes = set()  # 🔥 변경된 바이트 주소를 저장하는 set
    relocations = get_relocations(pe_file)

    for block in f.blocks:
        dag = build_bb_dependence_dag(block)
        block.rinstrs = reorder_graph_randomly(dag)
        del dag
        min_pos = block.instrs[0].pos

        order_changed = False
        reloc_diff = False
        for i, rins in enumerate(block.rinstrs):
            rins.raddr = block.begin if i == 0 else block.rinstrs[i - 1].raddr + len(block.rinstrs[i - 1].bytes)
            if rins.raddr != rins.addr:
                order_changed = True
                if rins.inst_len > 4 and causes_reloc_diff([rins], pe_file, relocations):
                    reloc_diff = True

        if order_changed and not reloc_diff:
            diff = inp.get_block_diff(block)
            diffs.extend(diff)

            # 🔥 변경된 바이트 주소 추가
            changed_bytes.update(ea for ea, orig, curr in diff)

            block.instrs = block.rinstrs
            for i, ins in enumerate(block.instrs):
                ins.addr = ins.raddr
                ins.pos = i + min_pos

        elif reloc_diff:
            block.rinstrs = block.instrs
            for ins in block.instrs:
                ins.raddr = ins.addr

    # ✅ 변경된 바이트 주소 set 반환 (정수가 아님)
    return diffs, changed_bytes



def causes_reloc_diff(rinstrs, pe, relocations):
    """
    Checks if relocating the instruction leads to a change in
    the reloc section. These cannot be handled well by this tool,
    it seems. Based on 'inp.get_reloc_diff()'.
    """
    base = pe.OPTIONAL_HEADER.ImageBase

    for rins in rinstrs:
        if rins.inst_len >= 5:  # 명령어 길이가 5바이트 이상인지 확인
            for rva in range(rins.addr - base + 1, rins.addr - base + rins.inst_len - 3):
                if rva in relocations:
                    return True
    return False



def get_relocations(pe):
    """PE 파일의 재배치(Relocation) 테이블을 분석"""
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_BASERELOC']])
    relocations = {}
    if hasattr(pe, 'DIRECTORY_ENTRY_BASERELOC'):
        for base_reloc in pe.DIRECTORY_ENTRY_BASERELOC:
            for reloc in [x for x in base_reloc.entries if x.type == 3]:
                relocations[reloc.rva] = reloc.struct.get_file_offset()
    return relocations

if __name__ == "__main__":
    import idaapi
    import inp_ida
    import func

    # IDA 내에서 현재 커서 위치의 함수 가져오기
    ida_func = idaapi.get_func(idaapi.get_screen_ea())
    if not ida_func:
        print("error: 커서가 함수 내부가 아닙니다.")
    else:
        func_ea = ida_func.start_ea
        code, blocks = inp_ida.get_code_and_blocks(func_ea)
        f = func.Function(func_ea, code, blocks, set(), set())
        for bb in f.blocks:
            if bb.begin <= idaapi.get_screen_ea() < bb.end:
                print(f"\n기본 블록 {hex(bb.begin)}:{hex(bb.end)}의 DAG 생성 중...")
                dag = build_bb_dependence_dag(bb)
                for ins in reorder_graph_randomly(dag):
                    print(ins)
                break
        else:
            print("기본 블록을 찾을 수 없습니다.")