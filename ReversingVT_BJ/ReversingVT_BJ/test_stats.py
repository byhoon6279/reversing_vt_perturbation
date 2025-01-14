# import util
import os
import sys
import json
import lief
# import perturbation as p
from multiprocessing import Pool
from modifier import Modifier

spath = "/data/beomjin/reversingVT/reversing_vt_perturbation/sample/input_sample/"
slist = os.listdir(spath)

for s in slist:
    # sample = "putty.exe"
    sample = spath + s
    mod = Modifier(sample, "m_sample")
    # mod.overlay_append()
    # mod.perturb_header()
    # mod.modify_dos_header()
    # mod.extend_dos_header()
    # mod.content_shifting()
    # mod.section_add()
    # mod.section_append()
    # mod.jmp_overlay_back()
    # mod.section_rename()
    # mod.rich_header()
    # mod.optional_header()
    # mod.coff_header()
    # mod.data_directory()
    try:
        mod.overlay_append()
    except:
        pass
    try:
        mod.perturb_header()
    except:
        pass
    try:
        mod.modify_dos_header()
    except:
        pass
    try:
        mod.extend_dos_header()
    except:
        pass
    try:
        mod.content_shifting()
    except:
        pass
    try:
        mod.section_add()
    except:
        pass
    try:
        mod.section_append()
    except:
        pass
    try:
        mod.jmp_overlay_back()
    except:
        pass
    try:
        mod.section_rename()
    except:
        pass
    try:
        mod.rich_header()
    except:
        pass
    try:
        mod.optional_header()
    except:
        pass
    try:
        mod.coff_header()
    except:
        pass
    try:
        mod.data_directory()
    except:
        pass
