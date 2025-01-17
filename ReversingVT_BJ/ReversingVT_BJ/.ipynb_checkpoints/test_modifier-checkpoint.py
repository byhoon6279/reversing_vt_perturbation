# import util
import os
import sys
import json
import lief
# import perturbation as p
from multiprocessing import Pool
from modifier import Modifier

perts = ["modify_dos_header","dos_stub","coff_header","rich_header","optional_header",
        "section_rename","section_add","section_append","content_shifting",
        "jmp_overlay_back","overlay_append","instruction_change","resource_change","increase_section"]

perts = ["instruction_change","resource_change","increase_section"]

sample = "putty.exe"
mod = Modifier(sample, "m_sample_2")

for pert in perts:
    print (pert)
    eval("mod.{}()".format(pert))

'''
mod.overlay_append()
mod.perturb_header()
# mod.fill_slack_space()
mod.modify_dos_header()
mod.extend_dos_header()
mod.content_shifting()
# mod.inject_import_func()
mod.section_add()
mod.section_append()
# mod.packing()
# mod.code_randomization()
# mod.change_entrypoint()
# mod.dropper()
# mod.extend_entrypoint()
# mod.nop_insertion()
mod.jmp_overlay_back()
'''
