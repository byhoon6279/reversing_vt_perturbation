#!/usr/bin/env python

import optparse
import itertools
import random
import subprocess
import os
import sys
import pefile
import copy
import capstone  # ✅ Capstone 추가
import pygraph

import func
import eval
import inp
import swap
import reorder
import equiv
import preserv
import shlex

VER = "0.3"

# ✅ Capstone 설정 (x86 32-bit 모드)
md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
md.detail = True  # 레지스터 사용 정보 활성화

def disassemble_instruction(code, address):
    """ ✅ Capstone을 사용하여 디스어셈블링 및 레지스터 정보 추출 """
    capstone_insn = next(md.disasm(code, address), None)
    if capstone_insn:
        return {
            "mnemonic": capstone_insn.mnemonic,
            "op_str": capstone_insn.op_str,
            "regs_read": capstone_insn.regs_read,  # ✅ 읽는 레지스터
            "regs_write": capstone_insn.regs_write,  # ✅ 쓰는 레지스터
        }
    return None

def patch(pe_file, diffs):
    """
    patch the pe_file according to the provided diffs
    (i.e., apply the diffs). The code is based on inp.patch().
    """
    base = pe_file.OPTIONAL_HEADER.ImageBase
    for ea, orig, new in diffs:
        if ea < base:
            if not pe_file.set_bytes_at_offset(ea, new):
                print("Error setting bytes at offset:", hex(ea))
        else:
            curr = pe_file.get_data(ea - base, len(orig))
            if curr != orig:
                print(f"Error in patching {hex(ea)}: {int.from_bytes(curr, 'little')} != {int.from_bytes(orig, 'little')}")
            if not pe_file.set_bytes_at_rva(ea - base, new):
                print("Error setting bytes at RVA:", hex(ea))

def randomize(input_file, n_randomize=10):
    pe_file = pefile.PE(input_file)

    functions = inp.get_functions(input_file)
    levels = func.classify_functions(functions)
    func.analyze_functions(functions, levels)

    for i_r in range(n_randomize):
        functions = copy.copy(functions)

        global_diffs = []
        changed_bytes = set()
        changed_insts = set()

        for f in [x for x in iter(functions.values()) if x.level != -1]:
            if "_SEH_" in f.name:
                continue

            # ✅ Capstone 기반 레지스터 분석 추가
            for ins in f.instrs:
                disas_result = disassemble_instruction(ins.bytes, ins.addr)
                if disas_result:
                    ins.mnemonic = disas_result["mnemonic"]
                    ins.USE = set(disas_result["regs_read"])
                    ins.DEF = set(disas_result["regs_write"])

            diffs, c_b, c_i = equiv.do_equiv_instrs(f)
            if diffs:
                changed_bytes.update(c_b)
                changed_insts.update(c_i)
                global_diffs.extend(diffs)
                patch(pe_file, diffs)

            swap.liveness_analysis(f.code)
            live_regs = swap.get_reg_live_subsets(f.instrs, f.code, f.igraph)
            swaps = swap.get_reg_swaps(live_regs)
            diffs, c_b, c_i = swap.do_multiple_swaps(f, swaps)
            if diffs:
                changed_bytes.update(c_b)
                changed_insts.update(c_i)
                global_diffs.extend(diffs)
                patch(pe_file, diffs)

            preservs, avail_regs = preserv.get_reg_preservations(f)
            diffs, c_b, c_i = preserv.do_reg_preservs(f, preservs, avail_regs)
            if diffs:
                changed_bytes.update(c_b)
                changed_insts.update(c_i)
                global_diffs.extend(diffs)
                patch(pe_file, diffs)

            diffs, c_b = reorder.do_random_reordering(f, pe_file)
            if diffs:
                changed_bytes.update(c_b)
                global_diffs.extend(diffs)
                patch(pe_file, diffs)

        print(f"✅ Done with randomization iter #{i_r}: changed {len(changed_bytes)} bytes and {len(changed_insts)} instructions")

        if i_r < n_randomize - 1:
            for f in functions.values():
                f.arg_regs = set()
                f.ret_regs = set()
                f.pre_regs = set()
                f.reg_pairs = []
            func.analyze_functions(functions, levels)

    output_file = input_file.replace(".exe", "_patched-w-compositions.exe")
    pe_file.write(output_file)
    pe_file.close()

def call_ida(input_file):
    script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "inp_ida.py")
    if not os.path.exists(script):
        print("❌ error: could not find inp_ida.py (%s)" % script)
        sys.exit(1)
    command = f'/opt/idapro-8.3/idat -A -S"{script}" {input_file}'
    print("🔄 executing:", command)
    exit_code = subprocess.call(shlex.split(command))
    print("🔄 exit code:", exit_code)

if __name__ == "__main__":
    parser = optparse.OptionParser("usage: %prog [options] input_file_or_directory")

    parser.add_option("-d", "--dump-cfg", dest="dump_cfg", action="store_true", default=False, help="dump the CFG of the input file (using IDA)")
    parser.add_option("-r", "--randomize", dest="randomize", action="store_true", default=True, help="produce a randomized instance of input (default)")
    parser.add_option("-D", "--dir", dest="directory", action="store", type="string", help="Specify a directory to process all .exe files")

    (options, args) = parser.parse_args()

    print(f"🔄 Orp v{VER}")

    if options.directory:
        for exe in [f for f in os.listdir(options.directory) if f.endswith(".exe")]:
            input_file = os.path.join(options.directory, exe)
            print(f"Processing {input_file} ...")

            if options.dump_cfg:
                call_ida(input_file)
            elif options.randomize:
                randomize(input_file)

        sys.exit(0)

    if len(args) == 0:
        parser.error("No input file")
    elif len(args) > 1:
        parser.error("More than one input file")

    if options.dump_cfg:
        call_ida(args[0])
    elif options.randomize:
        randomize(args[0])
