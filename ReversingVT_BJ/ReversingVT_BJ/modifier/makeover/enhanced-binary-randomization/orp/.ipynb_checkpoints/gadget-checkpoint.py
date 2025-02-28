#!/usr/bin/env python3

import pickle
import inp
import util
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

# Capstone 초기화
md = Cs(CS_ARCH_X86, CS_MODE_32)


class SimpleGadget(object):
  
    def __init__(self, start, end, overlap, red, ins_num, func_ea):
        self.start = start
        self.end = end  # real end!
        self.overlap = overlap
        self.red = red
        self.ins_num = ins_num
        self.func_ea = func_ea

    def set_extra(self, addrs, string, end_func_ea):
        self.addrs = addrs
        self.string = string
        self.end_func_ea = end_func_ea


class Gadget:
  
    def __init__(self, start_ea, end_ea, instrs):
        self._start_ea = start_ea
        self._end_ea = end_ea  # addr of the first byte of the final instruction
        self._instrs = instrs
        self.overlap = not all((a in inp.get_code_heads() for a, i in instrs))

    def get_start_ea(self):
        return self._start_ea

    def get_end_ea(self):
        return self._end_ea

    def get_real_end_ea(self):
        return self._end_ea + self._instrs[-1][1].size

    def dump_simple(self, extra=False):
        func_ea = inp.get_func_of(self._start_ea)
        red = (not func_ea and not inp.get_func_of(self.get_real_end_ea() - 1))
        sg = SimpleGadget(self._start_ea, self.get_real_end_ea(), self.overlap,
                          red, len(self._instrs), func_ea)
        if extra:
            sg.set_extra(
                [a for a, i in self._instrs],
                '; '.join([i.mnemonic + " " + i.op_str for a, i in self._instrs]),
                inp.get_func_of(self.get_real_end_ea() - 1)
            )
        return sg

    def __str__(self):
        output_header = "gadget @ %.08X:%.08X %s\n" % (
            self.get_start_ea(), self.get_end_ea(),
            "(overlapping)" if self.overlap else ""
        )
        output_lines = []
        for ea, instr in self._instrs:
            output_lines.append("%.08X %.2X %s %s" % (
                ea, instr.bytes[0], instr.mnemonic, instr.op_str))
        return output_header + '\n'.join(output_lines)


gadget_ends = [0xC3, 0xC2, 0xFF]  # ret, ret imm16, indirect jmp/call

def find_gadget_ends(start_ea, end_ea):
    gadget_end_addresses = []
    ea = start_ea
    while ea < end_ea:
        opcode = inp.byte_at(ea)
        if opcode in gadget_ends:
            gadget_end_addresses.append(ea)
        ea += 1
    return gadget_end_addresses


def extract_gadget(end_ea, depth_bytes=64):
    """Extract all gadgets ending at a given address using Capstone."""
    bytes_back = depth_bytes
    ibuf_start = max(end_ea - bytes_back, inp.seg_start(end_ea))
    ibuf_len = bytes_back
    ibuf = inp.bytes_at(ibuf_start, ibuf_len)

    if not ibuf:
        print(f"WARNING: Failed to get bytes at {hex(ibuf_start)}")
        return []

    gadgets = []
    for instr in md.disasm(ibuf, ibuf_start):
        if instr.address == end_ea:
            instrs = [(i.address, i) for i in md.disasm(ibuf, instr.address)]
            gadgets.append(Gadget(instrs[0][0], instrs[-1][0], instrs))
    return gadgets


def find_gadgets(ea_start, ea_end):
    gadgets = set()
    gadget_end_addresses = find_gadget_ends(ea_start, ea_end)
    for g_ea in sorted(gadget_end_addresses):
        gadgets.update(extract_gadget(g_ea))
    return gadgets


def find_gadgets5(ea_start, ea_end):
    gadgets5 = set()
    for g in find_gadgets(ea_start, ea_end):
        for i in range(min(5, len(g._instrs)), 1, -1):
            instrs = g._instrs[-i:]
            gadgets5.add(Gadget(instrs[0][0], instrs[-1][0], instrs))
    return gadgets5


def find_payload_gadgets():
    payload = util.get_payload(inp.get_input_file_path())
    exp_gadgets = set()

    for addr in payload:
        gadgets = find_gadgets(addr, addr + 64)
        for gad in gadgets:
            for iaddr, ins in gad._instrs:
                if iaddr == addr:
                    i = gad._instrs.index((iaddr, ins))
                    exp_gadgets.add(Gadget(addr, gad._instrs[-1][0], gad._instrs[i:]))

    print(f"Found {len(exp_gadgets)} gadgets for {len(payload)} addresses")

    if len(exp_gadgets) != len(payload):
        print("Missing:", list(set(payload) - set(g.get_start_ea() for g in exp_gadgets)))

    return {g.dump_simple(extra=True) for g in exp_gadgets}


def get_all_gadgets():
    all_gadgets = set()
    for begin, end, name in inp.code_segments_iter():
        all_gadgets |= find_gadgets5(begin, end)
    return all_gadgets


def get_simple_gadgets(input_file):
    try:
        with util.open_gadgets(input_file, "rb") as gad_in:
            simple_gadgets = pickle.load(gad_in, encoding="latin1")
    except IOError:
        all_gadgets = get_all_gadgets()
        simple_gadgets = {g.dump_simple(extra=True) for g in all_gadgets}
        with util.open_gadgets(input_file, "wb") as gad_out:
            pickle.dump(simple_gadgets, gad_out)
    return simple_gadgets


def get_payload_gadgets(input_file):
    try:
        with util.open_payload_gadgets(input_file, "rb") as pay_gad_in:
            payload_gadgets = pickle.load(pay_gad_in, encoding="latin1")
    except IOError:
        payload_gadgets = find_payload_gadgets()
        with util.open_payload_gadgets(input_file, "wb") as pay_gad_out:
            pickle.dump(payload_gadgets, pay_gad_out)
    return payload_gadgets


if __name__ == "__main__":
    start_ea = inp.get_screen_ea()
    end_ea = inp.get_func_end(start_ea)
    print(f"\nSearching for gadgets in {hex(start_ea)}:{hex(end_ea)}")
    gadgets = find_gadgets(start_ea, end_ea)
    print(f"Found {len(gadgets)} gadgets:")
    for g in sorted(gadgets):
        print(g)
    gadgets5 = find_gadgets5(start_ea, end_ea)
    print(f"Found {len(gadgets5)} (sub)sequences 2-5 instructions long")
    for g in sorted(gadgets5):
        print(g)
