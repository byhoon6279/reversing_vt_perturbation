import capstone

REGS = ("eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi")
NON_32BIT_REGS = {"al", "ah", "ax", "bl", "bh", "bx", "cl", "ch", "cx", "dl", "dh", "dx"}
NUM_REGS = 8

# Capstone disassembler initialization
CS_MODE = capstone.CS_MODE_32  # 32비트 모드 설정
md = capstone.Cs(capstone.CS_ARCH_X86, CS_MODE)
md.detail = True

class Operand:
    NONE = capstone.x86.X86_OP_INVALID
    MEMORY = capstone.x86.X86_OP_MEM
    REGISTER = capstone.x86.X86_OP_REG
    IMMEDIATE = capstone.x86.X86_OP_IMM

    def __init__(self, capstone_op):
        self.type = capstone_op.type
        self.immediate_value = capstone_op.imm if self.type == self.IMMEDIATE else None
        
class Instruction:
    def __init__(self, ea, bytes, spd=0):
        self.addr = ea
        self.bytes = bytes
        self.spd = spd  # Stack pointer delta
        self.disas = ""
        self.mnem = ""
        self.eflags_r = set()
        self.eflags_w = set()
        self.succ = set()
        self.USE = set()
        self.DEF = set()
        self.IN = set()
        self.OUT = set()
        self.regs = {}
        self.implicit = set()
        self.irreplaceable = False
        self.f_entry = False
        self.f_exit = False
        self.pos = -1
        self.raddr = ea
        self.updated = False
        self.can_change = set()
        self.cregs = None
        self.cbytes = None
        self.creg_names = None
        self.IN_old = None
        self.OUT_old = None
        self.inst_len = 0
        self.modrm_off = None
        self.opc_off = None
        self.uses_sib = False
        self.type = None
        self.operands = []
        
        try:
            insts = list(md.disasm(bytes, ea))
            if not insts:
                return

            inst = insts[0]
            self.disas = inst.mnemonic + " " + inst.op_str
            self.mnem = inst.mnemonic
            self.operands = [Operand(op) for op in inst.operands]
            
            # eflags_read, eflags_write 대신 regs_read, regs_write 사용
            self.eflags_r = set(inst.regs_read) if hasattr(inst, "regs_read") else set()
            self.eflags_w = set(inst.regs_write) if hasattr(inst, "regs_write") else set()

            self.f_exit = self.mnem == "ret"
            self.inst_len = inst.size
            self.type = inst.id
            self.modrm_off = inst.modrm_offset if hasattr(inst, 'modrm_offset') else None
            self.opc_off = inst.opcode_offset if hasattr(inst, 'opcode_offset') else None
        except Exception as e:
            print(f"[ERROR] Failed to decode instruction at {hex(ea)}: {e}")

        self._get_use_def(inst)
        self._store_operands(inst)
        self.reset_changed()

    def is_ind_call(self):
        return self.mnem == "call" and self.bytes[0] == 0xFF
    
    def reset_changed(self):
        self.cregs = self.regs.copy()
        self.cbytes = bytearray(self.bytes)
        self.creg_names = {}

    def apply_changes(self):
        self.regs = self.cregs.copy()
        self.bytes = bytes(self.cbytes)
        insts = list(md.disasm(self.bytes, self.addr))
        if insts:
            inst = insts[0]
            self.disas = inst.mnemonic + " " + inst.op_str
            self.mnem = inst.mnemonic
            self.eflags_r = set(inst.eflags_read if inst.eflags_read else [])
            self.eflags_w = set(inst.eflags_write if inst.eflags_write else [])
        self.reset_changed()
        
    def swap_registers(self, r1, r2):
        """Swaps registers and verifies correctness of the resulting instruction.
        Returns False if the swap is incorrect or has no effect.
        On success, 'cregs' and 'cbytes' are updated accordingly.
        """
        if r1 not in self.regs or r2 not in self.regs:
            return False

        def update_bits(register1, register2, byte_array, reg_map):
            for byte_off, bit_off in reg_map[register1]:
                clear_mask = ~(0b111 << bit_off)
                byte_array[byte_off] &= clear_mask
                set_mask = REGS.index(register2) << bit_off
                byte_array[byte_off] |= set_mask

        try:
            new_bytes = bytearray(self.cbytes)
            update_bits(r1, r2, new_bytes, self.cregs)
            update_bits(r2, r1, new_bytes, self.cregs)

            # Decode the modified instruction
            new_inst = list(md.disasm(new_bytes, self.addr))
            if not new_inst or new_inst[0].mnemonic != self.mnem:
                return False

            # Check if mnemonic remains the same
            if new_inst[0].mnemonic != self.mnem:
                return False

            # Apply the changes
            self.cbytes = new_bytes
            self.cregs[r1], self.cregs[r2] = self.cregs[r2], self.cregs[r1]

            return True
        except Exception as e:
            print(f"[ERROR] Swap failed at {hex(self.addr)}: {e}")
            return False

    def _store_operands(self, inst):
        """ Stores operands and decodes ModRM and SIB information """
        self.operands = [Operand(op) for op in inst.operands]
        registers = []

        # Handling ModRM byte
        if self.modrm_off is not None and self.modrm_off < len(inst.bytes):
            rm = inst.bytes[self.modrm_off] & 0b111
            reg = (inst.bytes[self.modrm_off] >> 3) & 0b111
            mod = (inst.bytes[self.modrm_off] >> 6) & 0b11

            self.modrm_rm = rm
            self.modrm_reg = reg
            self.modrm_mod = mod

            # Decode registers based on ModRM encoding
            if not ((mod != 0b11 and rm == 0b100) or (mod == 0b00 and rm == 0b101)):
                registers.append([REGS[rm], self.modrm_off, 0])

            elif mod != 0b11 and rm == 0b100:  # SIB 존재
                if self.modrm_off + 1 < len(inst.bytes):  # **길이 검사 추가**
                    try:
                        index = (inst.bytes[self.modrm_off + 1] >> 3) & 0b111
                        base = inst.bytes[self.modrm_off + 1] & 0b111

                        if index != 0b100:
                            registers.append([REGS[index], self.modrm_off + 1, 3])
                        if base != 0b101 or (base == 0b101 and mod in (0b01, 0b10)):
                            registers.append([REGS[base], self.modrm_off + 1, 0])
                        self.uses_sib = True
                    except IndexError:
                        print(f"[ERROR] ModRM SIB index out of range at {hex(self.addr)}")
                else:
                    print(f"[WARNING] ModRM SIB byte is missing at {hex(self.addr)}")

            # Handle second operand in ModRM
            if len(self.operands) > 1 and self.operands[1].type == Operand.REGISTER:
                registers.append([REGS[reg], self.modrm_off, 3])

        # Store register encoding positions
        self.regs = {}
        for reg, byte_off, bit_off in registers:
            if reg not in self.regs:
                self.regs[reg] = []
            self.regs[reg].append((byte_off, bit_off))
            
    def _is_reg_in_opcode(self, inst):
        """
        Determines if the register is encoded in the opcode.
        Handles instructions like inc, dec, push, pop, mov, bswap.
        """
        if not inst or not hasattr(inst, 'id'):
            return False

        # Check if the instruction's ID is among those that encode a register in the opcode
        opcodes_with_reg = {
            capstone.x86.X86_INS_INC, capstone.x86.X86_INS_DEC,
            capstone.x86.X86_INS_PUSH, capstone.x86.X86_INS_POP,
            capstone.x86.X86_INS_MOV, capstone.x86.X86_INS_XCHG,
            capstone.x86.X86_INS_BSWAP
        }

        return inst.id in opcodes_with_reg

    def not32bit(self, op_i, inst=None):
        """
        Checks if the operand op_i is not a 32-bit register.
        Assumes that the operand is a register.
        """
        if inst is None:
            insts = list(md.disasm(self.bytes, self.addr))
            if not insts:
                return False
            inst = insts[0]

        if op_i >= len(inst.operands):
            return False  # Out of bounds check
        
        operand = inst.operands[op_i]
        if operand.type != capstone.x86.X86_OP_REG:
            return False  # Not a register operand

        reg_name = md.reg_name(operand.reg)
        return reg_name in NON_32BIT_REGS
    
    def _get_use_def(self, inst):
        """
        Identifies which registers are used (read) and defined (written) by the instruction.
        """

        if not inst:
            return
        
        # Special case: Ignore 'mov R, R' (redundant move used in patching)
        if self.mnem == "mov" and len(inst.operands) == 2:
            if (inst.operands[0].type == capstone.x86.X86_OP_REG and
                inst.operands[1].type == capstone.x86.X86_OP_REG and
                inst.operands[0].reg == inst.operands[1].reg):
                return

        # Special case: XOR R, R → Zero out register (only DEF, no USE)
        if self.mnem == "xor" and len(inst.operands) == 2:
            if (inst.operands[0].type == capstone.x86.X86_OP_REG and
                inst.operands[1].type == capstone.x86.X86_OP_REG and
                inst.operands[0].reg == inst.operands[1].reg):
                reg_name = md.reg_name(inst.operands[0].reg)
                if reg_name in NON_32BIT_REGS:
                    self.DEF.add(REGS[inst.operands[0].reg % 4])
                    self.USE.add(REGS[inst.operands[0].reg % 4])
                else:
                    self.DEF.add(reg_name)
                return

        # Special case: REP-prefixed instructions → Implicitly use ECX
        if "rep" in self.mnem:
            self.USE.add("ecx")
            self.DEF.add("ecx")
            self.implicit.add("ecx")

        # Special case: CMOVcc (Conditional Move)
        if self.mnem.startswith("cmov") and len(inst.operands) >= 2:
            for i, op in enumerate(inst.operands[:2]):  # Check first two operands
                if op.type == capstone.x86.X86_OP_REG:
                    reg_name = md.reg_name(op.reg)
                    if i == 0:  # Destination register (May be both USE and DEF)
                        self.DEF.add(reg_name)
                        self.USE.add(reg_name)
                    else:  # Source register (Only USE)
                        self.USE.add(reg_name)
                elif op.type == capstone.x86.X86_OP_MEM:
                    if op.mem.base:
                        self.USE.add(md.reg_name(op.mem.base))
                    if op.mem.index:
                        self.USE.add(md.reg_name(op.mem.index))

        # Special case: SHRD & SHLD
        if self.mnem in {"shrd", "shld"}:
            for op in inst.operands:
                if op.type == capstone.x86.X86_OP_REG:
                    reg_name = md.reg_name(op.reg)
                    self.USE.add(reg_name)
                    if op == inst.operands[0]:  # First operand is the destination
                        self.DEF.add(reg_name)
                elif op.type == capstone.x86.X86_OP_MEM:
                    if op.mem.base:
                        self.USE.add(md.reg_name(op.mem.base))
                    if op.mem.index:
                        self.USE.add(md.reg_name(op.mem.index))
            return

        # Normal case: Handle all operands
        for op in inst.operands:
            if op.type == capstone.x86.X86_OP_REG:
                reg_name = md.reg_name(op.reg)
                if op.access & capstone.CS_AC_READ:
                    self.USE.add(reg_name)
                if op.access & capstone.CS_AC_WRITE:
                    self.DEF.add(reg_name)
            elif op.type == capstone.x86.X86_OP_MEM:
                if op.mem.base:
                    self.USE.add(md.reg_name(op.mem.base))
                if op.mem.index:
                    self.USE.add(md.reg_name(op.mem.index))

        # Implicit registers used by the instruction
        for reg in inst.regs_read:
            self.USE.add(md.reg_name(reg))
            self.implicit.add(md.reg_name(reg))

        for reg in inst.regs_write:
            self.DEF.add(md.reg_name(reg))
            self.implicit.add(md.reg_name(reg))

    def __repr__(self):
        """
        Returns a developer-friendly string representation of the instruction.
        """
        return f"{hex(self.addr)}: {self.disas} ({' '.join(f'{b:02x}' for b in self.bytes)})"

    def __str__(self):
        """
        Returns a human-readable representation of the instruction.
        """
        byte_str = ' '.join(f"{b:02x}" for b in self.bytes)  # Python 3 방식으로 변환
        return f"{self.pos:3d}: 0x{self.addr:08X} {self.disas}\t({byte_str})"
