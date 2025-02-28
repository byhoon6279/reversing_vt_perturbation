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
    # Reset instruction and function states
    for a, f in functions.items():
        if f.level == -1:
            continue
        
        # Re-init functions that were reordered
        if hasattr(f, "code"):
            code = f.code
            was_reordered = any(ins_a != f.code[ins_a].addr for ins_a in f.code)
            
            if was_reordered:
                code2 = {ins.addr: ins for ins in code.values()}
                f2 = func.Function(f.addr, code2, f.blocks, f.code_refs_to, f.code_refs_from)

                # Copy attributes from original function
                f2.name = f.name
                f2.exported = f.exported
                f2.ftype = f.ftype
                f2.level = f.level
                functions[a] = f2
        
        # Update calls/rets
        for ref, func_ea in f.code_refs_to:
            try:
                # Re-init the data structures
                f2 = functions[func_ea]
                f2.code[ref].USE.clear()
                f2.code[ref].DEF.clear()
                f2.code[ref].implicit.clear()
                f2.code[ref].updated = False
            except KeyError:
                pass  # Function reference not found

        # Reset CALL instructions
        for ins in filter(lambda x: x.mnem == "call", f.instrs):
            ins.can_change.clear()
            ins.USE.clear()
            ins.DEF.clear()
            ins.implicit.clear()

        # Reset EXIT instructions
        for ins in filter(lambda x: x.f_exit, f.instrs):
            ins.USE.clear()
            ins.implicit.clear()

        # Reset data structures for functions that weren’t reordered
        for ins in f.instrs:
            ins.reset_changed()
            ins.apply_changes()
            ins.updated = False
        
        # Reset function-level attributes
        f.arg_regs.clear()
        f.ret_regs.clear()
        f.pre_regs.clear()
        f.reg_pairs.clear()
    
    # Run function-level analysis
    func.analyze_functions(functions, levels)

def patch(pe_file, disp_state, diffs, force_patch=False):
    """
    Patch the pe_file according to the provided diffs
    (i.e., apply the diffs). The code is based on inp.patch().
    
    If `force_patch` is True, it will overwrite even if `orig` doesn't match `curr`.
    """
    base = pe_file.OPTIONAL_HEADER.ImageBase
    
    for ea, orig, new in diffs:
        # Ensure `new` is in bytes format
        if isinstance(new, int):
            new = bytes([new])  # Convert single int to bytes
        elif isinstance(new, list):
            new = bytes(new)  # Convert list of ints to bytes

        if (disp_state is None) or (ea < disp_state.ropf_start):  # Non-displaced instruction
            if ea < base:
                if not pe_file.set_bytes_at_offset(ea, new):
                    print(f"⚠️ Error setting bytes at offset: {hex(ea)}")
            else:
                curr = pe_file.get_data(ea - base, len(new))  # Ensure correct length
                
                # Ensure `curr` and `orig` are bytes before comparison
                if isinstance(curr, int):
                    curr = bytes([curr])
                if isinstance(orig, int):
                    orig = bytes([orig])

                if orig is not None and curr != orig:
                    if force_patch:
                        print(f"⚠️ Warning: Overwriting different bytes at {hex(ea)}: {curr.hex()} -> {new.hex()}")
                    else:
                        print(f"❌ Error in patching {hex(ea)}: Expected {orig.hex()}, but found {curr.hex()}")
                        continue  # Skip this patch

                if not pe_file.set_bytes_at_rva(ea - base, new):
                    print(f"⚠️ Error setting bytes at RVA: {hex(ea)}")


