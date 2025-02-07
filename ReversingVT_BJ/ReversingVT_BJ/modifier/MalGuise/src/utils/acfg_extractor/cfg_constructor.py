# coding:utf-8

import copy
import networkx as nx
from idautils import *
import idaapi
from idc import *
from graph_analysis_ida import *
import jsonlines

def write_data_to_filename(filename, data):
    with jsonlines.open(filename, mode='a') as writer:
        writer.write(data)

def getCfg(func, externs_eas, ea_externs):
#     func_start = func.startEA
#     func_end = func.endEA
    func_start = func.start_ea
    func_end = func.end_ea
    
    cfg = nx.DiGraph()
    control_blocks = obtain_block_sequence(func)
    
    visited = {}
    for bl in control_blocks:
        start = control_blocks[bl][0]
        end = control_blocks[bl][1]
        src_node = (start, end)
        if src_node not in visited:
            src_id = len(cfg)
            visited[src_node] = src_id
            cfg.add_node(src_id)
            #cfg.node[src_id]['label'] = src_node
            cfg.nodes[src_id]['label'] = src_node
        else:
            src_id = visited[src_node]

        if start == func_start:
            #cfg.node[src_id]['c'] = "start"
            cfg.nodes[src_id]['c'] = "start"
            # start_node = src_node
        if end == func_end:
            #cfg.node[src_id]['c'] = "end"
            cfg.nodes[src_id]['c'] = "end"

        refs = CodeRefsTo(start, 0)
        for ref in refs:
            if ref in control_blocks:
                dst_node = control_blocks[ref]
                if dst_node not in visited:
                    visited[dst_node] = len(cfg)
                dst_id = visited[dst_node]
                cfg.add_edge(dst_id, src_id)
                #cfg.node[dst_id]['label'] = dst_node
                cfg.nodes[dst_id]['label'] = dst_node

        refs = CodeRefsTo(start, 1)
        for ref in refs:
            if ref in control_blocks:
                dst_node = control_blocks[ref]
                if dst_node not in visited:
                    visited[dst_node] = len(cfg)
                dst_id = visited[dst_node]
                cfg.add_edge(dst_id, src_id)
                #cfg.node[dst_id]['label'] = dst_node
                cfg.nodes[dst_id]['label'] = dst_node

    cfg = attributingRe(cfg, externs_eas, ea_externs)
    return cfg


# def attributingRe(cfg, externs_eas, ea_externs):
#     for node_id in cfg:
#         bl = cfg.node[node_id]['label']

#         TransferInsNum, DateDefInsNum, TerminationInsNum, MovInsNum, CompareInsNum, CallsNum, ArithmeticInsNum, LogicInstructionsNum, InstsNum = cal_all_attribute(bl)

#         cfg.node[node_id]['numIns'] = InstsNum

#         cfg.node[node_id]['numCalls'] = CallsNum

#         cfg.node[node_id]['numLIs'] = LogicInstructionsNum

#         cfg.node[node_id]['numAs'] = ArithmeticInsNum

#         strings, consts = getBBconsts(bl)
#         cfg.node[node_id]['numNc'] = len(strings) + len(consts)
#         cfg.node[node_id]['consts'] = consts
#         cfg.node[node_id]['strings'] = strings

#         cfg.node[node_id]['numTIs'] = TransferInsNum

#         cfg.node[node_id]['numCmpIs'] = CompareInsNum

#         cfg.node[node_id]['numMovIs'] = MovInsNum

#         cfg.node[node_id]['numTermIs'] = TerminationInsNum

#         cfg.node[node_id]['numDefIs'] = DateDefInsNum

#     return cfg

def attributingRe(cfg, externs_eas, ea_externs):
    for node_id in cfg:
        bl = cfg.nodes[node_id]['label']

        TransferInsNum, DateDefInsNum, TerminationInsNum, MovInsNum, CompareInsNum, CallsNum, ArithmeticInsNum, LogicInstructionsNum, InstsNum = cal_all_attribute(bl)

        cfg.nodes[node_id]['numIns'] = InstsNum

        cfg.nodes[node_id]['numCalls'] = CallsNum

        cfg.nodes[node_id]['numLIs'] = LogicInstructionsNum

        cfg.nodes[node_id]['numAs'] = ArithmeticInsNum

        strings, consts = getBBconsts(bl)
        cfg.nodes[node_id]['numNc'] = len(strings) + len(consts)
        cfg.nodes[node_id]['consts'] = consts
        cfg.nodes[node_id]['strings'] = strings

        cfg.nodes[node_id]['numTIs'] = TransferInsNum

        cfg.nodes[node_id]['numCmpIs'] = CompareInsNum

        cfg.nodes[node_id]['numMovIs'] = MovInsNum

        cfg.nodes[node_id]['numTermIs'] = TerminationInsNum

        cfg.nodes[node_id]['numDefIs'] = DateDefInsNum

    return cfg

def obtain_block_sequence(func):
    control_blocks = {}
    #blocks = [(v.startEA, v.endEA) for v in idaapi.FlowChart(func)]
    blocks = [(v.start_ea, v.end_ea) for v in idaapi.FlowChart(func)]
    for bl in blocks:
        base = bl[0]
        #if (func.startEA <= base <= func.endEA) or SegName(base).count('htext') > 0 or SegName(base).count('ropf') > 0:
        if (func.start_ea <= base <= func.end_ea) or idc.get_segm_name(base).count('htext') > 0 or idc.get_segm_name(base).count('ropf') > 0:
            control_ea = checkCB(bl)
            control_blocks[control_ea] = bl
    return control_blocks

def checkCB(bl):
    start = bl[0]
    end = bl[1]
    ea = start
    while ea < end:
        if checkCondition(ea):
            return ea
        #ea = NextHead(ea)
        ea = idc.next_head(ea)
    #return PrevHead(end)
    return idc.prev_head(end)


def checkCondition(ea):
    mips_branch = {"beqz": 1, "beq": 1, "bne": 1, "bgez": 1, "b": 1, "bnez": 1, "bgtz": 1, "bltz": 1, "blez": 1,
                   "bgt": 1, "bge": 1, "blt": 1, "ble": 1, "bgtu": 1, "bgeu": 1, "bltu": 1, "bleu": 1}
    x86_branch = {"jz": 1, "jnb": 1, "jne": 1, "je": 1, "jg": 1, "jle": 1, "jl": 1, "jge": 1, "ja": 1, "jae": 1,
                  "jb": 1, "jbe": 1, "jo": 1, "jno": 1, "js": 1, "jns": 1, "jmp": 1, "jnz": 1}
    arm_branch = {"B": 1, "BAL": 1, "BNE": 1, "BEQ": 1, "BPL": 1, "BMI": 1, "BCC": 1, "BLO": 1, "BCS": 1, "BHS": 1,
                  "BVC": 1, "BVS": 1, "BGT": 1, "BGE": 1, "BLT": 1, "BLE": 1, "BHI": 1, "BLS": 1}
    conds = {}
    conds.update(mips_branch)
    conds.update(x86_branch)
    #opcode = GetMnem(ea)
    opcode = idc.print_insn_mnem(ea)
    if opcode in conds:
        return True
    return False
