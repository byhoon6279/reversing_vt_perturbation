# Copyright (c) 2012, Vasilis Pappas <vpappas@cs.columbia.edu>
# This file is part of Orp http://nsl.cs.columbia.edu/projects/orp

# Additionally modified by Mahmood Sharif <mahmoods@alumni.cmu.edu>
# Alternate contact is Keane Lucas <keanelucas@cmu.edu>

import itertools
import inp
from collections import deque
import random
import randtoolkit

from pygraph.algorithms.filters.null import null as null_filter
from pygraph.algorithms.searching import breadth_first_search
from functools import reduce
import capstone

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)

class Lifetime:
  """Represents the lifetime of a register as a set of "Subsets"."""

  def __init__(self, name, max_span_size):
    self.regions  = []
    self.subsets  = []
    self.name     = name
    self.span     = [None]*max_span_size # optimize region lookups 
    self.max_size = max_span_size

  def get_reg_name_in(self, begin, end):
    names = set(self.cname[begin:end+1])-set([None])
    if len(names) == 0: #dead
      return self.name
    elif len(names) == 1:
      return names.pop()
    else: # more than one names !?
      # be conservative here and filter the combination ..
      return None #self.name #names.pop()

  def update_reg_name_in(self, begin, end, name):
    self.cname[begin:end+1] = [name]*(end-begin+1)

  def reset_name(self):
    self.cname = [None]*self.max_size
    for r in self.regions:
      self.cname[r.begin:r.end+1] = [self.name]*(r.end-r.begin+1)

  def dont_touch(self):
    return len(self.subsets) == 0 or (len(self.subsets) == 1 and 
                           self.subsets[0].size == self.max_size)

  def add_subset(self, instrs):
    # subsets of the same register may overlap overlap, mostly due to 
    # one instruction live regions
    new_subset = Subset(instrs, self.name)
    for subset in self.subsets[:]: #copy because it changes
      if subset.intersects(new_subset):
        new_subset.merge(subset)
        self.subsets.remove(subset)
    self.subsets.append(new_subset)

  def get_swap_subset(self, subset, other):
    #get a copy of subset!
    subset = subset.copy()
    #print "will check", self.name, other.name, "in", subset

    for lifetime in itertools.cycle((self, other)):
      old_size = subset.size
      for sg in lifetime.subsets:
        if sg.intersects(subset):
          #print "\t", sg, "intersects", subset
          if sg.no_swap:
            #print "\tsg is no swap .. bail out"
            return None
          #print "\tmerging them!"
          subset.merge(sg)
      if subset.size == old_size:
        #print "\tsize did not change, done!"
        break

    return subset

  def __str__(self):
    return "%s (dont_touch=%-5s): %s" % (self.name, self.dont_touch(), 
                            ", ".join(map(str, self.subsets)))

  def __repr__(self):
    return self.name


class Subset:
  """Represents a subset of the CFG (instructions only, sufficient
  and much faster)"""
  
  def __init__(self, instrs, register):
    # check whether region is unswappable and make the graph
    self.instr_set = set()
    self.no_swap = False
    for ins in instrs:
          # check if register is implicitly used
      if not self.no_swap and ((register in ins.implicit) or
          # check if reg was alive before the function was called
          (ins.f_entry and register in ins.IN) or
          # for now, we assume that every register that is alive at exit
          # may be used by the caller (return value(s))
          (ins.f_exit and register in ins.USE)):
        self.no_swap = True
      self.instr_set.add(ins)
    self.size = len(self.instr_set)
 
  def merge(self, other):
    self.instr_set.update(other.instr_set)
    self.size = len(self.instr_set)
    self.no_swap = self.no_swap or other.no_swap

  def intersects(self, other):
    # fast, no copies
    return len(self.instr_set & other.instr_set) > 0 #any((n in self.instr_set for n in other.instr_set))

  def copy(self):
    copy_subset = Subset([], '')
    copy_subset.instr_set = self.instr_set.copy()
    copy_subset.size = self.size
    copy_subset.no_swap = self.no_swap
    return copy_subset
 
  # mostly for debug
  def to_graph(self, code):
    graph = digraph()
    graph.add_nodes(self.instr_set)
    for ins in self.instr_set:
      for suc in ins.succ:
        if graph.has_node(code[suc]):
          graph.add_edge((ins, code[suc]))
    return graph
 
  def __str__(self):
    return "%s no_swap=%s" % ([min((i.pos for i in self.instr_set)), 
           max((i.pos for i in self.instr_set))], self.no_swap)


class Swap:
  """Simple class to hold swaps."""
  def __init__(self, reg1, reg2, subset):
    self.reg1, self.reg2 = sorted([reg1, reg2], key=lambda r: r.name)
    self.regs = {self.reg1, self.reg2}
    self.size = subset.size
    self.addrs = tuple(sorted(i.addr for i in subset.instr_set))
    self.subset = subset
    self._id = f"{self.reg1.name}-{self.reg2.name}-{sorted(self.subset.instr_set, key=lambda x: x.addr)[0].addr}"

  def get_instrs(self):
    return self.subset.instr_set

  def overlap(self, other):
    return self.subset.instr_set & other.subset.instr_set

  def __eq__(self, other):
    return (isinstance(other, Swap) and self._id == other._id)

  def __hash__(self):
    return hash(self._id)
 
  def __repr__(self):
    return f"{self.reg1.name} <-> {self.reg2.name} ({len(self.subset.instr_set)}) in: {[min((i.pos for i in self.subset.instr_set)), max((i.pos for i in self.subset.instr_set))]}"
  
  def bounds(self):
    """
    Returns the min position and max position of the instructions
    covered by the swap.
    """
    return [min((i.pos for i in self.subset.instr_set)), \
            max((i.pos for i in self.subset.instr_set))]

def liveness_analysis(code):
    """Performs instruction-level liveness analysis using Capstone and fills the IN/OUT sets."""
    
    # ✅ Capstone 초기화 (Detail 활성화)
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True  # 🔥 핵심 옵션 추가

    convergence = False
    i = 0

    # Initialize the liveness sets
    for ins in code.values():
        ins.IN = set()
        ins.OUT = set()
    
    while not convergence:
        i += 1
        for ins in reversed(code.values()):
            ins.IN_old = ins.IN.copy()
            ins.OUT_old = ins.OUT.copy()

            # out[n] = U_{s is successor of n} in[s]
            ins.OUT = reduce(lambda x, y: x | y, [code[s].IN for s in ins.succ], set())

            # ✅ Capstone 명령어 분석
            capstone_insn = next(md.disasm(ins.bytes, ins.addr), None)

            if capstone_insn:
                try:
                    ins.USE = set(capstone_insn.regs_read)
                    ins.DEF = set(capstone_insn.regs_write)
                except capstone.CsError:
                    ins.USE = set()
                    ins.DEF = set()
                    print(f"⚠️ Capstone failed to retrieve register details at {hex(ins.addr)}")

                # Call instruction 처리
                if capstone_insn.mnemonic == 'call':
                    ins.IN = ins.USE | ins.implicit | (ins.OUT - ins.DEF)
                else:
                    ins.IN = ins.USE | (ins.OUT - ins.DEF)

        # Check for convergence
        for ins in code.values():
            if (ins.IN_old != ins.IN) or (ins.OUT_old != ins.OUT):
                break
        else:
            convergence = True



def get_reg_live_subsets(instrs, code, igraph):
    """
    Computes the subsets of the instructions where each register is live.
    Returns a dictionary keyed with the register name.
    """

    general_regs = {"eax", "ebx", "ecx", "edx", "edi", "esi", "ebp", "esp"}
    extended_regs = {"ax", "bx", "cx", "dx", "di", "si", "bp", "sp"}  # 16-bit 레지스터 추가
    byte_regs = {"al", "ah", "bl", "bh", "cl", "ch", "dl", "dh"}  # 8-bit 레지스터 추가
    special_regs = {"eip", "eflags", "fpsw"}
    fpu_regs = {"st(0)", "st(1)", "st(2)", "st(3)", "st(4)", "st(5)", "st(6)", "st(7)"}
    mmx_regs = {"mm0", "mm1", "mm2", "mm3", "mm4", "mm5", "mm6", "mm7"}
    sse_regs = {"xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5", "xmm6", "xmm7"}

    # 🔥 모든 고려해야 하는 레지스터 합치기
    all_valid_regs = general_regs | extended_regs | byte_regs | special_regs | fpu_regs | mmx_regs | sse_regs


    # 🔥 모든 레지스터를 처리할 수 있도록 초기화
    live_regs = {reg: Lifetime(reg, len(instrs)) for reg in all_valid_regs}

    class LiveFilter(null_filter):
        def __call__(self, other, node):
            return node is None or self.cur_reg in other.IN

    live_f = LiveFilter()
    for ins in instrs:
        diff = ins.OUT - ins.IN
        if len(diff) > 1 and ins.mnem in {"call", "cpuid", "rdtsc"}:
            print(f"WARNING: More than one regs defined at {ins} {ins.OUT} {ins.IN}")

        for reg in diff:
            if isinstance(reg, int):  # 🔥 정수형 레지스터 변환
                reg = md.reg_name(reg)
                if not reg:  # 변환 실패 시 무시
                    print(f"⚠️ Warning: Unknown register ID {reg} encountered, skipping...")
                    continue

            if reg not in all_valid_regs:
                print(f"⚠️ Warning: Skipping unexpected register '{reg}' in DEF.")
                continue

            live_f.cur_reg = reg
            _, order = breadth_first_search(igraph, ins, live_f)
            live_regs[reg].add_subset(order)

    # Handle one-instruction live regions
    for ins in instrs:
        for reg in ins.DEF:
            if isinstance(reg, int):  # 🔥 정수형 변환
                reg = md.reg_name(reg)
                if not reg:
                    print(f"⚠️ Warning: Unknown register ID {reg} encountered, skipping...")
                    continue

            if reg not in all_valid_regs:
                print(f"⚠️ Warning: Skipping unexpected register '{reg}' in DEF.")
                continue

            if reg not in ins.OUT:
                live_regs[reg].add_subset([ins])

    # Handle live registers from function entry
    if not instrs[0].f_entry:
        print("BUG: compute_live: instrs[0] is not f_entry!!!")

    for reg in instrs[0].IN:
        if isinstance(reg, int):  # 🔥 정수형 변환
            reg = md.reg_name(reg)
            if not reg:
                print(f"⚠️ Warning: Unknown register ID {reg} encountered, skipping...")
                continue

        if reg not in all_valid_regs:
            print(f"⚠️ Warning: Skipping unexpected register '{reg}' in function entry.")
            continue

        live_f.cur_reg = reg
        _, order = breadth_first_search(igraph, instrs[0], live_f)
        live_regs[reg].add_subset(order)

    return live_regs





#TODO: splitting is not 100% .. first, we stop after we find just one split
# per subset (there could be cases that we would be able to prune more) and
# second, we should recursively check all the possible subsubsets .. not just
# simple spits
def split_reg_live_subsets(live_regs, code):
  """Checks whether the computed live subsets can be split. A live subset can be
  split when it contains an isntruction that USEs and DEFs the same register, thus
  ending and beginning new subsets."""

  def _split_subset_at(instr_set, at, code):
    #print "lets do", instr_set, at, code
    # find the subset after the indirect call
    after = set()
    queue = set((code[s] for s in at.succ if code[s] in instr_set))
    while len(queue) > 0:
      ins = queue.pop()
      after.add(ins)
      queue.update((code[s] for s in ins.succ if code[s] in instr_set and code[s] not in after))
    #print "after", after
    #XXX sneaky: check for rhombus weird stuff!
    succs = set()
    for ins in instr_set - after - set((at,)):
      succs.update((code[s] for s in ins.succ if code[s] in instr_set))
    #print "succs", succs
    if succs & after:
      #print "WARNING: rhombus in split!", at
      return None, None
    if at in after:
      print(("WARNING: cycle!", at))
      return None, None
    before = instr_set - after - set((at,))
    return before, after
  
  def _unswappable_subsets_iter():
    for reg in list(live_regs.values()):
      for subset in (s for s in reg.subsets if s.no_swap):
        yield reg, subset
    return

  def recursive_split(reg, subset, code, changes):
    for ins in subset.instr_set:
      # check if we have a indirect call and split the region in two!
      if reg.name in ins.implicit and reg.name in ins.can_change:
        before_call, after_call = _split_subset_at(subset.instr_set, ins, code) 
        if before_call == after_call == None:
          continue
        # we check whether the region ending before the call would be swappable
        # if so, we split it!
        if Subset(before_call, reg.name).no_swap == False:
          #print "yeii we're splitting!!"
          sub1 = Subset(before_call | set((ins,)), reg.name)
          sub1.no_swap = False #we have to manually change it here ..
          if len(after_call) > 0: #no need if last ins is our call
            sub2 = Subset(after_call, reg.name)
            sub2.no_swap = True #we have to manually change it here ..
            changes.append((reg, subset, (sub1, sub2)))
            recursive_split(reg, sub2, code, changes)
          else:
            changes.append((reg, subset, (sub1,)))
          break
      # check if we have mov or lea instructions that have the same src, dst
      # XXX: this is a quick and dirty implementation: we only search for 
      # unswappable regions that contain these kind of instructions and then,
      # if spliting these regions would produce a swappable part, we split it
      elif ins.mnem in ("movzx", "movsx", "mov", "lea") and set((reg.name,)) == (ins.DEF & ins.USE):
        before, after = _split_subset_at(subset.instr_set, ins, code)
        #print ins, before, after
        if before == after == None:
          continue
        if Subset(before | set((ins,)), reg.name).no_swap == False:
          sub1 = Subset(before | set((ins,)), reg.name)
          sub2 = Subset(after, reg.name)
          changes.append((reg, subset, (sub1, sub2)))
          ins.cregs[reg.name].remove((ins.modrm_off, 3))
          recursive_split(reg, sub2, code, changes)
          break
        elif Subset(set((ins,)) | after, reg.name).no_swap == False:
          sub1 = Subset(before, reg.name)
          sub2 = Subset(set((ins,)) | after, reg.name)
          changes.append((reg, subset, (sub1, sub2)))
          #print ins.regs, '->',
          ins.cregs[reg.name] = [(ins.modrm_off, 3)]
          #print ins.regs
          recursive_split(reg, sub1, code, changes)
          break
    return

  changes = []
  for reg, subset in _unswappable_subsets_iter():
    recursive_split(reg, subset, code, changes)
  for reg, subset, subs in changes:
    reg.subsets.remove(subset)
    reg.subsets.extend(subs)
  return


def get_reg_swaps(live_regs):
    """Finds all possible register swaps using Capstone."""
    swaps = []
    reg_vals = [x for x in live_regs.values() if not x.dont_touch()]

    for reg, other in itertools.permutations(reg_vals, 2):
        for subset in reg.subsets:
            if subset.no_swap:
                continue
            swap_subset = other.get_swap_subset(subset, reg)
            if swap_subset is not None and swap_subset.size > 0:
                swaps.append(Swap(reg, other, swap_subset))

    return swaps



def apply_swap_comb(swap_comb):
    """Applies each swap in the combination by updating Capstone disassembly."""
    
    changed = set()
    failed = False
    
    for swap in swap_comb:
        for ins in swap.get_instrs():
            if swap.reg1.name in ins.regs or swap.reg2.name in ins.regs:
                changed.add(ins)
                if not ins.swap_registers(swap.reg1.name, swap.reg2.name):
                    failed = True
                    break

    return not failed, changed


def bound_comparison(swap1, swap2):
  """
  Compare the bounds of two swaps; returns 0 for no
  overlap, 1 for overlap, and -1 for partial overlap.
  Assumes that the range of swap1 is larger than swap2's.
  """
  instrs1 = swap1.subset.instr_set
  instrs2 = swap2.subset.instr_set
  if instrs2.issubset(instrs1):
    return 1
  if len(instrs1 & instrs2)>0:
    return -1
  return 0
  # bounds1 = swap1.bounds()
  # bounds2 = swap2.bounds()
  # if bounds2[1]<bounds1[0] or bounds1[1]<bounds2[0]:
  #   return 0
  # if bounds1[0]<=bounds2[0] and bounds2[1]<=bounds1[1]:
  #   return 1
  # return -1

def reg_overlap(swap1, swap2):
  """
  returns True if swap1 and swap2 have any register in common
  """
  if swap1.reg1.name==swap2.reg1.name or \
     swap1.reg1.name==swap2.reg2.name or \
     swap1.reg2.name==swap2.reg1.name or \
     swap1.reg2.name==swap2.reg2.name:
    return True
  return False

def swap_to_key(swap):
    """
    주어진 swap 객체에 대해 정렬 가능한 키를 생성하는 함수.
    - 레지스터 순서를 유지하면서 bounds 값을 활용하여 고유한 정렬 키를 만듦.
    """
    regs = ['eax', 'ebx', 'ecx', 'edx', 'edi', 'esi', 'ebp', 'esp']
    reg_to_idx = {reg: idx for idx, reg in enumerate(regs)}

    # swap의 범위를 가져옴
    bounds = swap.bounds()
    start, end = bounds[0], bounds[1]

    # swap 대상 레지스터 인덱스 가져오기
    reg1_idx = reg_to_idx.get(swap.reg1.name, -1)  # 존재하지 않으면 -1 (예외 방지)
    reg2_idx = reg_to_idx.get(swap.reg2.name, -1)

    # 정렬을 위한 키 생성
    key = (end - start) * 1_000_000  # 범위 길이에 가중치 부여
    key += start * 100  # 시작 주소 반영
    key += max(reg1_idx, reg2_idx) * 10  # 큰 레지스터 인덱스 우선
    key += min(reg1_idx, reg2_idx)  # 작은 레지스터 인덱스 추가

    return key


def can_swap(f):
  """
  checks if there are any pairs of registers in f
  that can be swapped.
  """
  liveness_analysis(f.code)
  live_regs = get_reg_live_subsets(f.instrs, f.code, f.igraph)
  swaps = get_reg_swaps(live_regs)
  if len(swaps)>0:
    return True
  return False

def do_multiple_swaps(f, swaps, p=0.5):
  """
  Do (randomly selected) multiple swaps at once. Applies the 
  changes to instructions directly, and returns a list of changes 
  to bytes (as well as sets of bytes and instructions changed).
  """
  
  # if no swaps, do nothing
  if not swaps:
    return [], set(), set()
  
  # order swap by # instructions covered (descending)
  ord_swaps = deque(sorted(swaps, key=lambda x: x.size, reverse=True))
  
  # find groups of overlapping swaps (code from
  # swap.gen_swap_combinations)
  swap_groups = []
  group_i = 0
  if len(swaps) > 0:
    swap_groups.append([ord_swaps.popleft()])
  while len(ord_swaps) > 0:
    old_len = len(swap_groups[group_i])
    for i in range(len(ord_swaps)):
      swap = ord_swaps.popleft()
      if any([swap.overlap(o) for o in swap_groups[group_i]]):
        swap_groups[group_i].append(swap)
      else:
        ord_swaps.append(swap)
    if len(swap_groups[group_i]) == old_len:
      group_i += 1
      swap_groups.append([ord_swaps.popleft()])
  for swap_group in swap_groups:
    swap_group.sort(key=lambda swap: swap_to_key(swap), reverse=True)
    
  # for each group of overlapping swaps, pick
  # a random subset of swaps to perform
  diffs = []
  changed_bytes = set()
  changed_instrs = set()
  for i_g, group in enumerate(swap_groups):
    group = deque(group)
    while(len(group)>0):
      swap = group.popleft()
      if random.random()<1-p:
        continue
      success, changed = apply_swap_comb([swap])
      if success:
        # compute diff, update changed addresses+instrs, and apply changes
        diff = inp.get_diff(changed)
        diffs.extend(diff)
        changed_bytes.update((ea for ea, orig, curr in diff))
        changed_instrs.update(changed)
        for ins in changed:
          ins.apply_changes()
        # update the next swaps (renaming registers where needed)
        group_prev = group
        group = deque([])
        for swap2 in group_prev:
          bound_res = bound_comparison(swap, swap2)
          reg_res = reg_overlap(swap, swap2)
          if bound_res==0 or not reg_res:
            group.append(swap2)
          elif bound_res==1:
            if swap2.reg1.name==swap.reg1.name:
              swap2.reg1 = swap.reg2
            elif swap2.reg1.name==swap.reg2.name:
              swap2.reg1 = swap.reg1
            if swap2.reg2.name==swap.reg1.name:
              swap2.reg2 = swap.reg2
            elif swap2.reg2.name==swap.reg2.name:
              swap2.reg2 = swap.reg1
            group.append(swap2)
      else:
        # failure
        for ins in f.instrs:
          ins.reset_changed()
  
  # reset instruction changes
  for ins in f.instrs:
    ins.reset_changed()
  
  # done
  return diffs, changed_bytes, changed_instrs

def do_swap_canonicalization(f, swaps, pe_file):
  """
  Canonicalize instructions to the representation with the minimal 
  alphabetical order.
  """
  # if no swaps, do nothing
  if not swaps:
    return [], set(), set()
  
  # order swap by # instructions covered (descending)
  ord_swaps = deque(sorted(swaps, key=lambda x: x.size, reverse=True))
  
  # find groups of overlapping swaps (code from
  # swap.gen_swap_combinations)
  swap_groups = []
  group_i = 0
  if len(swaps) > 0:
    swap_groups.append([ord_swaps.popleft()])
  while len(ord_swaps) > 0:
    old_len = len(swap_groups[group_i])
    for i in range(len(ord_swaps)):
      swap = ord_swaps.popleft()
      if any([swap.overlap(o) for o in swap_groups[group_i]]):
        swap_groups[group_i].append(swap)
      else:
        ord_swaps.append(swap)
    if len(swap_groups[group_i]) == old_len:
      group_i += 1
      swap_groups.append([ord_swaps.popleft()])
  for swap_group in swap_groups:
    swap_group.sort(key=lambda swap: swap_to_key(swap), reverse=True)

  # for each group of overlapping swaps, pick the
  # swaps that would decrease the alphabetical order
  diffs = []
  changed_bytes = set()
  changed_instrs = set()
  for i_g, group in enumerate(swap_groups):
    group = deque(group)
    while(len(group)>0):
      swap = group.popleft()
      success, changed = apply_swap_comb([swap])
      if success:
        # compute diff
        diff = inp.get_diff(changed)
        # check if the diff decreases the alphabetical order
        earliest = min(diff, key=lambda x: x[0])
        if earliest[2]>earliest[1]:
          # the diff isn't good
          for ins in f.instrs:
            ins.reset_changed()
          continue
        # diff is good (decreases the order)
        diffs.extend(diff)
        changed_bytes.update((ea for ea, orig, curr in diff))
        changed_instrs.update(changed)
        for ins in changed:
          ins.apply_changes()
        # update the next swaps (renaming registers where needed)
        group_prev = group
        group = deque([])
        for swap2 in group_prev:
          bound_res = bound_comparison(swap, swap2)
          reg_res = reg_overlap(swap, swap2)
          if bound_res==0 or not reg_res:
            group.append(swap2)
          elif bound_res==1:
            if swap2.reg1.name==swap.reg1.name:
              swap2.reg1 = swap.reg2
            elif swap2.reg1.name==swap.reg2.name:
              swap2.reg1 = swap.reg1
            if swap2.reg2.name==swap.reg1.name:
              swap2.reg2 = swap.reg2
            elif swap2.reg2.name==swap.reg2.name:
              swap2.reg2 = swap.reg1
            group.append(swap2)
      else:
        # failure
        for ins in f.instrs:
          ins.reset_changed()
  
  # reset instruction changes
  for ins in f.instrs:
    ins.reset_changed()

  # apply diffs
  randtoolkit.patch(pe_file, None, diffs)
  
  # done
  return diffs, changed_bytes, changed_instrs

def do_single_swaps(swaps, gen_patched, all_diffs=None):
  """Applies one swap at a time and optionally generates the patched .dll.
  Returns a set of the linear addresses of the changed bytes."""

  changed_bytes = set()
  
  for i, swap in enumerate(swaps):
    success, changed = apply_swap_comb([swap])

    if success:
      diff = inp.get_diff(changed)
      if gen_patched:
        inp.patch(diff, "swap-%06d"%i)
      if all_diffs != None:
        all_diffs.append(diff)
      changed_bytes.update((ea for ea, orig, curr in diff))

    for ins in changed:
      ins.reset_changed()

  return changed_bytes


def gen_swap_combinations(swaps):
  """Generates all the possible swap combinations (entropy)."""

  # check 0x4A8297A0, icu
  from collections import deque

  ord_swaps = deque(sorted(swaps, key=lambda x: x.size, reverse=True))

  # categorize swaps in groups of overlapping ones
  swap_groups = []
  group_i = 0

  if len(swaps) > 0:
    swap_groups.append([ord_swaps.popleft()])

  while len(ord_swaps) > 0:

    old_len = len(swap_groups[group_i])

    for i in range(len(ord_swaps)):

      swap = ord_swaps.popleft()

      if any([swap.overlap(o) for o in swap_groups[group_i]]):
        swap_groups[group_i].append(swap)
      else:
        ord_swaps.append(swap)

    if len(swap_groups[group_i]) == old_len:
      group_i += 1
      swap_groups.append([ord_swaps.popleft()])

  comb_groups = []

  for group in swap_groups:
    #print(len(group), group)
    combs = [itertools.combinations(group, i) for i in range(len(group)+1)]
    #print(len(combs), combs)
    comb_groups.append(itertools.chain(*combs))
    #print(type((*comb_groups[0])[1]))

  for comb in itertools.product(*comb_groups):
    comb = [x for x in itertools.chain(*comb) if x]
    if len(comb) > 0:
      yield comb


# executes as an IDA python script
if __name__ == "__main__":
  import inp_ida
  import func

  # Find swappable registers in the function under the cursor
#  ida_func = idaapi.get_func(ScreenEA())
  ida_func = idaapi.get_func(idaapi.get_screen_ea())  # ✅ 최신 버전 호환

  if not ida_func:
    print("error: cursor is not under a function..")
  else:
    func_ea = ida_func.startEA
    print(("\nAnalyzing function starting at %X" % func_ea))
    code, blocks = inp_ida.get_code_and_blocks(func_ea)
    f = func.Function(func_ea, code, blocks, set(), set())
    # treat as unclassified 
    f.update_calls()
    f.analyze_registers({})
    f.update_returns(set_default=True)

    print(f)

    for ins in f.instrs:
      print(("%-40s R: %-12s W: %-12s I: %s" % (str(ins), 
            ','.join(ins.USE), ','.join(ins.DEF), ','.join(ins.implicit))))

    print("\nRunning liveness analysis")
    liveness_analysis(f.code)

    for ins in f.instrs:
      print(("%-40s IN: %-20s OUT: %-20s" % (str(ins), 
            ','.join(ins.IN), ','.join(ins.OUT))))

    print("\nComputing the live instruction subsets of the registers")
    live_regs = get_reg_live_subsets(f.instrs, f.code, f.igraph)

    for reg in list(live_regs.values()):
      print(reg)

    print("\nTrying to split some of the subsets")
    split_reg_live_subsets(live_regs, code)

    for reg in list(live_regs.values()):
      print(reg) 

    print("\nComputing the possible register swaps")
    swaps = get_reg_swaps(live_regs)
    for i, swap in enumerate(swaps):
      print((i, swap)) 
