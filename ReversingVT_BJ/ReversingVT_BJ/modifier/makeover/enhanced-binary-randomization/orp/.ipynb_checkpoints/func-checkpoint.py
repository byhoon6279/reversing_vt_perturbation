import capstone
import bbl
import insn

from pygraph.classes.digraph import digraph
from pygraph.algorithms.searching import depth_first_search, breadth_first_search
from pygraph.algorithms.filters.null import null as null_filter

# ✅ 기본적인 x86 레지스터 집합
REGS = ("eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi")

# ✅ 사용된 레지스터 필터
class _use_filter(null_filter):
    def __init__(self, helperdict={}):
        self.use_regs = set()
        self.all_regs = set(REGS)
        self.helperdict = helperdict

    def __call__(self, other, node):
        if other.addr in self.helperdict:
            self.use_regs |= self.helperdict[other.addr]
            return False

        self.use_regs |= (self.all_regs & other.USE)
        self.all_regs -= other.DEF
        return True

# ✅ 정의된 레지스터 필터
class _def_filter(null_filter):
    def __init__(self, reg):
        self.reg = reg
        self.last_ins = None

    def __call__(self, other, node):
        self.last_ins = other
        if node and self.reg in other.DEF:
            return False
        return True


import networkx as nx  # 그래프 처리를 위해 사용
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64

class Function:
    def __init__(self, addr, code, blocks, crefs_to, crefs_from):
        """
        Function 객체를 초기화합니다.

        :param addr: 함수의 시작 주소
        :param code: 함수의 코드 딕셔너리
        :param blocks: 함수의 블록 리스트
        :param crefs_to: 함수로의 코드 참조 목록
        :param crefs_from: 함수에서의 코드 참조 목록
        """
        self.addr = addr
        self.code = code
        self.blocks = blocks
        self.arg_regs = set()  # 레지스터 인자
        self.ret_regs = set()  # 레지스터 반환 값
        self.pre_regs = set()  # 보존된 레지스터
        self.touches = set()  # USE 또는 DEF된 레지스터 (보존되지 않음)
        self.reg_pairs = []  # push/pop 레지스터 페어 저장
        self.ftype = None
        self.name = None
        self.exported = False
        self.level = -2  # 레벨 (-1: import, 0이상: 분석된 함수)
        self.code_refs_to = crefs_to  # 함수로의 코드 참조

        if code:  # 코드가 있는 경우 (import된 함수가 아닐 경우)
            self.instrs = self._reorder_instructions()
            self.igraph = self._get_instrs_graph()
            self.code_refs_from = crefs_from

    def __del__(self):
        """
        객체가 삭제될 때 메모리를 정리합니다.
        """
        if self.code:
            del self.igraph
            del self.instrs
            del self.code_refs_from
            del self.code

        del self.addr
        del self.blocks
        del self.code_refs_to
        del self.arg_regs
        del self.ret_regs
        del self.pre_regs
        del self.touches
        del self.reg_pairs
        del self.ftype
        del self.name

    def _reorder_instructions(self):
        """
        함수 내의 명령어를 정렬하여 재배치합니다.
        """
        cfg = nx.DiGraph()  # 방향성 그래프 (Control Flow Graph)
        cfg.add_nodes_from(self.blocks)

        for block in self.blocks:
            for other in block.successors:
                cfg.add_edge(block, other)

        # 함수의 진입점 블록 찾기
        root = next((b for b in self.blocks if b.type & bbl.BasicBlock.ENTRY), None)
        instrs = []

        if root:
            span_tree = list(nx.dfs_postorder_nodes(cfg, root))  # DFS 기반 재정렬
            for block in reversed(span_tree):
                instrs.extend(block.instrs)

            instrs[0].f_entry = True  # 첫 번째 명령어는 함수 진입점
        
            # 명령어 순서 업데이트
            for i, ins in enumerate(instrs):
                ins.pos = i

        del cfg  # 그래프 메모리 해제
        return instrs

    def _get_instrs_graph(self):
        """
        명령어 그래프를 생성합니다.
        """
        instr_graph = nx.DiGraph()
        instr_graph.add_nodes_from(self.instrs)

        for i, ins in enumerate(self.instrs[:-1]):
            instr_graph.add_edge(ins, self.instrs[i + 1])

        return instr_graph
    
      # can be called after analyze_registers and update the reg sets
    def parse_ftype(self, ftype):
        if ftype and isinstance(ftype, str):
            if not ftype.startswith("void"):
                self.ret_regs.add("eax")
            else:
                self.ret_regs.discard("eax")
            if "__cdecl" in ftype or "__stdcall" in ftype:
                self.touches.update(("eax", "ecx", "edx"))
            elif "__fastcall" in ftype:
                self.arg_regs.update(("ecx", "edx"))
                self.touches.update(("eax", "ecx", "edx"))
            elif "__thiscall" in ftype:
                self.arg_regs.add("ecx")
                self.touches.update(("eax", "ecx", "edx"))
            # Ensure proper preservation of registers
            self.pre_regs.update(('esi', 'edi', 'ebx', 'ebp', 'esp'))
            self.touches -= self.pre_regs


    def check_SEH_preservs(self, functions):
        """
        SEH (Structured Exception Handling) 관련 함수인지 검사하고, 보존해야 할 레지스터를 업데이트합니다.
        """
        for ref in self.code_refs_from:
            if ref in functions:
                name = functions[ref].name
                if name and ("SEH_prolog" in name or "SEH_epilog" in name):
                    self.pre_regs.update({"ebp", "esi", "edi", "ebx"})
                    return True
        return False

    def analyze_registers(self, functions):
        """ 
        함수의 레지스터 사용 분석을 수행하여 인자, 보존, 반환 레지스터를 식별합니다.
        """
        if self.name and ("SEH_prolog" in self.name or "SEH_epilog" in self.name):
            return

        use_f = _use_filter()
        if not self.instrs[0].f_entry:
            print("BUG: analyze_registers: instrs[0] is not f_entry!!!")

        st, order = breadth_first_search(self.igraph, self.instrs[0], use_f)

        if not self.check_SEH_preservs(functions):
            pushes, pops = [], []
            for ins in self.instrs:
                if ins.mnem == "leave" or (ins.mnem == "pop" and len(ins.operands) > 0 and 
                                           ins.operands[0].type == insn.Operand.REGISTER):
                    pops.append(ins)
                elif (ins.mnem == "push" and len(ins.operands) > 0 and 
                      ins.operands[0].type == insn.Operand.REGISTER and 
                      len(ins.USE & use_f.use_regs) > 1):
                    pushes.append(ins)

            last_ins_by_pop_and_reg = {}
            for push in pushes:
                if len(push.USE) != 2 or "esp" not in push.USE:
                    print("WEIRD push instruction !?:", push)
                    continue

                reg = (push.USE - {"esp"}).pop()
                reg_pops = list(filter(lambda x: reg in x.DEF, pops))
                if not reg_pops:
                    continue

                true_reg_pops = []
                for pop in reg_pops:
                    if (pop, reg) in last_ins_by_pop_and_reg:
                        last_ins = last_ins_by_pop_and_reg[(pop, reg)]
                    else:
                        def_f = _def_filter(reg)
                        st, order = breadth_first_search(self.igraph, pop, def_f)
                        last_ins_by_pop_and_reg[(pop, reg)] = def_f.last_ins
                        last_ins = def_f.last_ins

                    if last_ins.mnem not in {"ret", "retn", "jmp"}:
                        continue

                    true_reg_pops.append(pop)

                if true_reg_pops:
                    self.reg_pairs.append((reg, push, true_reg_pops))
                    self.pre_regs.add(reg)

        self.arg_regs = use_f.use_regs - self.pre_regs
        for ins in self.instrs:
            self.touches |= (ins.DEF | ins.USE)
        self.touches -= self.pre_regs

        if not self.arg_regs <= self.touches:
            print("BUG: how can arg_regs not be subset of touched?", self)

        subtree_dict = {}
        for ref, func_ea in self.code_refs_to:
            try:
                func = functions[func_ea]
                use_f = _use_filter(subtree_dict)
                st, order = breadth_first_search(func.igraph, func.code[ref], use_f)
                subtree_dict[ref] = use_f.use_regs
                self.ret_regs |= (use_f.use_regs & self.touches)
            except KeyError:
                pass


    def update_returns(self, set_default=False):
        """
        함수의 반환값 레지스터를 업데이트합니다.
        """
        for ins in filter(lambda x: x.f_exit, self.instrs):
            if set_default:
                ins.USE.update({"eax", "edx"} | self.ret_regs | self.pre_regs)
                ins.implicit.update({"eax", "edx"} | self.ret_regs | self.pre_regs)
            else:
                ins.USE.update({"eax"} | self.ret_regs | self.pre_regs)
                ins.implicit.update({"eax"} | self.ret_regs | self.pre_regs)

    def update_calls(self):
        """
        호출된 함수의 영향을 받는 레지스터를 업데이트합니다.
        """
        for ins in filter(lambda x: x.mnem == "call", self.instrs):
            if not ins.updated:
                ins.can_change.update(ins.USE - ins.implicit)
                ins.USE.update({"ecx", "edx"})
                ins.DEF.update({"eax", "ecx", "edx"})
                ins.implicit.update({"eax", "ecx", "edx"})

    def update_callers_info(self, functions):
        """
        호출자의 USE 및 DEF 집합을 업데이트합니다.
        """
        for ref, func_ea in self.code_refs_to:
            try:
                func = functions[func_ea]
                func.code[ref].USE.update(self.arg_regs)
                func.code[ref].DEF.update(self.touches)
                func.code[ref].implicit.update(self.touches | self.arg_regs)
                func.code[ref].updated = True
            except KeyError:
                pass

    def get_basic_block(self, start_ea, end_ea):
        """
        주어진 주소 범위에 해당하는 기본 블록을 검색합니다.
        """
        for bb in self.blocks:
            if bb.begin == start_ea and bb.end == end_ea:
                return bb
        return None

    def __str__(self):
        """
        함수의 기본 정보를 문자열로 반환합니다.
        """
        ret = f"0x{self.addr:X} level-{self.level}\n"
        ret += f"   arguments: {self.arg_regs}\n"
        ret += f"   touches  : {self.touches}\n"
        ret += f"   returns  : {self.ret_regs}\n"
        ret += f"   preserved: {self.pre_regs}\n"
        return ret

    def classify_functions(functions):
        """
        호출 관계를 분석하여 함수를 분류합니다.
        """
        level = 0
        processed, curr_processed = set(), set()

        while len(processed) < len(functions):
            curr_processed.clear()
            for func in filter(lambda x: x.level == -2, functions.values()):
                if func.code_refs_from <= processed:
                    func.level = level
                    curr_processed.add(func.addr)

            if curr_processed <= processed:
                curr_processed.clear()
                for func in filter(lambda x: x.level == -2, functions.values()):
                    if func.ftype:
                        func.level = level
                        curr_processed.add(func.addr)

                if not curr_processed:
                    break

            processed.update(curr_processed)
            level += 1

        return level


def classify_functions(functions):
    level = 0
    processed, curr_processed = set(), set()

    while len(processed) < len(functions):
        curr_processed.clear()
        for func in (f for f in functions.values() if f.level == -2):
            if func.code_refs_from and func.code_refs_from <= processed:
                func.level = level
                curr_processed.add(func.addr)

        if not curr_processed - processed:
            break

        processed.update(curr_processed)
        level += 1

    return level

# TODO: need to go through this again ..
def analyze_functions(functions, levels):
    """
    Analyzes functions by calling f.analyze_registers and updates
    the USE-DEF sets for call/ret functions.
    """

    # (imported) Update info on callers of imported functions
    for func in [f for f in functions.values() if f.level == -1]:
        func.parse_ftype(func.ftype)
        func.update_callers_info(functions)

    # (classified) Process each level of functions in order
    for l in range(levels):
        # print(f"\tanalyzing level-{l} functions")
        for func in [f for f in functions.values() if f.level == l]:
            func.analyze_registers(functions)

            # Special case for typed functions
            if func.ftype:  # Typed functions that call unclassified ones
                func.parse_ftype(func.ftype)  # Safe to call after analyze_registers

            func.update_callers_info(functions)
            func.update_returns()
            func.update_calls()

    # (unclassified) Set default USE and DEF values to any not updated calls
    # and all the returns. Such calls should only exist in unclassified functions.
    # print("\tanalyzing unclassified functions")
    for func in [f for f in functions.values() if f.level == -2]:
        func.update_calls()

    # Now analyze the unclassified methods too, mostly for preserved registers
    for func in [f for f in functions.values() if f.level == -2]:
        func.analyze_registers(functions)
        func.update_returns(set_default=True)

    for func in [f for f in functions.values() if f.level == -2]:
        func.update_callers_info(functions)  # XXX XXX

    # Count the number of updated call instructions
    calls = updated = 0
    for func in [f for f in functions.values() if hasattr(f, "instrs")]:
        for ins in [i for i in func.instrs if i.mnem == "call"]:
            calls += 1
            if ins.updated:
                updated += 1

    # print(f"\ttotal {calls}, updated {updated}")

