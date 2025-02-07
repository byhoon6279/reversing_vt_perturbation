# -*- coding: utf-8 -*- 
import os
import sys
import idc
import idaapi
import idautils
from idc import *
from idaapi import *
from idautils import *
import json
import jsonlines
import omegaconf
from pathlib import Path
import ida_pro
import ida_nalt

p = Path(os.path.abspath(__file__))
base_path = str(p.parents[3])

cfg_path = os.path.join(base_path, "configs/preprocess.yaml")
config = omegaconf.OmegaConf.load(cfg_path)

LogicInstructions_x86_LI = {'and': 1, 'andn': 1, 'andnpd': 1, 'andpd': 1, 'andps': 1, 'andnps': 1, 'test': 1, 'xor': 1, 'xorpd': 1, 'pslld': 1}
LogicInstructions_mips_LI = {'and': 1, 'andi': 1, 'or': 1, 'ori': 1, 'xor': 1, 'nor': 1, 'slt': 1, 'slti': 1, 'sltu': 1}
LogicInstructions_x86_mips = {}
LogicInstructions_x86_mips.update(LogicInstructions_x86_LI)
LogicInstructions_x86_mips.update(LogicInstructions_mips_LI)

cmps = [
		'cmp', 'cmpeqps', 'cmpeqsd', 'cmpeqss', 'cmpleps',
		'cmplesd', 'cmpltpd', 'cmpltps', 'cmpltsd', 'cmpneqpd',
		'cmpneqps', 'cmpnlepd', 'cmpnlesd', 'cmpps', 'cmps',
		'cmpsb', 'cmpsd', 'cmpsw', 'cmpxchg', 'comisd',
		'comiss',
		'cmpeqpd', 'cmpltss', 'cmpnleps', 'cmpnless',
		'cmpnltpd', 'cmpnltps', 'cmpnltsd', 'cmpnltss',
		'cmpunordpd', 'cmpunordps',
		'fcom', 'fcomi', 'fcomip', 'fcomp', 'fcompp', 'ficom', 'ficomp',
		'fucom', 'fucomi', 'fucomip', 'fucomp', 'fucompp',
		'pcmpeqb', 'pcmpeqd', 'pcmpeqw', 'pcmpgtb',
		'pcmpgtd', 'pcmpgtw', 'pfcmpeq', 'pfcmpge', 'pfcmpgt',
		'ucomisd', 'ucomiss',
		'vpcmpeqb', 'vpcmpeqd',
		'vpcmpeqw', 'vpcmpgtb', 'vpcmpgtd', 'vpcmpgtw', 'vucomiss',
		'vcmpsd', 'vcomiss', 'vucomisd',
	]

def write_data_to_filename(filename, data):
    with jsonlines.open(filename, mode='a') as writer:
        writer.write(data)

def obtain_block_sequence(func):
    control_blocks = {}
    blocks = [(v.start_ea, v.end_ea) for v in idaapi.FlowChart(func)]
    for bl in blocks:  # delete wrong blocks
        base = bl[0]
        control_ea = checkCB(bl)
        # control_blocks[hex(control_ea)] = [hex(bl[0]),hex(bl[1])]
    return [base, control_ea]

def checkCB(bl):
    start = bl[0]
    end = bl[1]
    ea = start
    while ea < end:
        if checkCondition(ea):
            return ea
        ea = idc.next_head(ea)
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
    opcode = print_insn_mnem(ea)
    if opcode in conds:
        return True
    return False

def get_seg_list():
	result = []
	total_seg_number = get_segm_qty()
	for n in range(total_seg_number):
		seg = getnseg(n)
		ea = seg.start_ea
		seg_type = segtype(ea)
		if seg_type in [1, 3, 7, 8, 9]:
			continue
		result.append(seg)
	return result


def get_blocks():
    binary_name = ida_nalt.get_root_filename()
    seg_list = get_seg_list()
    flag = False
    i = 0
    control_blocks = []
    for segm in seg_list:
        for funcea in Functions(segm.start_ea, segm.end_ea):
            func = get_func(funcea)
            blocks = [(v.start_ea, v.end_ea) for v in idaapi.FlowChart(func)]
            for bl in blocks:
                base = bl[0]
                control_ea = checkCB(bl)
                control_blocks.append((base, control_ea))
    return control_blocks

def get_call_instruction():
    total_call_instruction = []
    control_blocks = get_blocks()
    for bl in control_blocks:
        have_logic = False
        have_cmp = False
        start = bl[0]
        end = bl[1]
        inst_addr = start
        while inst_addr < end:
            opcode = idc.print_insn_mnem(inst_addr)
            if opcode in cmps:
                have_cmp = True
            if opcode in LogicInstructions_x86_mips:
                have_logic = True
            if idc.print_insn_mnem(inst_addr).lower() == 'call' and idc.get_operand_type(inst_addr, 0) == o_near and idc.print_operand(inst_addr, 0).strip().lower().startswith('sub_'):
                try:
                    next_line = idc.next_head(inst_addr)
                    target_addr = '0x' + idc.print_operand(inst_addr, 0).split('_')[1]
                    total_call_instruction.append((str(hex(inst_addr)), str(hex(next_line)), target_addr, have_logic, have_cmp))
                    have_logic = False
                    have_cmp = False
                    # print(hex(line), idc.idc.get_operand_type(line, 0), idc.print_operand(line, 0))
                except Exception as e:
                    pass
            inst_addr = idc.next_head(inst_addr)
    return total_call_instruction


def main():
    filename = ida_nalt.get_root_filename()
    #saved_path = os.path.join(base_path, config.saved_path)
    saved_path = ida_nalt.get_input_file_path().replace(filename,'')
    
    data_path = os.path.join(saved_path, filename+".txt")
    total_call_instruction = get_call_instruction()
    write_data_to_filename(data_path, total_call_instruction)


if __name__ == '__main__':
    ida_auto.auto_wait()
    #main()
    try:
        main()
        ida_pro.qexit(0)
    except:
        ida_pro.qexit(0)
