# import util
import os
import sys
import json
import lief
# import perturbation as p
from multiprocessing import Pool
from modifier import Modifier

# perts = ["modify_dos_header","dos_stub","coff_header","rich_header","optional_header",
#         "section_rename","section_add","section_append","content_shifting",
#         "jmp_overlay_back","overlay_append","instruction_change","resource_change","increase_section", "semantic_nop", "makeover"]

perts = ["modify_dos_header","extend_dos_stub","coff_header","rich_header","optional_header",
        "section_rename","section_add","section_append","content_shifting",
        "jmp_overlay_back","overlay_append","instruction_change","resource_change","section_increase"]

perts = ["instruction_change"]

#input_dir = '../../semi_measure/Seed_malware/'
#save_dir =  '../../semi_measure/AE/'

input_dir = './'
save_dir =  './m_sample_2'

#input_dir = '../../sample/benign/'
#save_dir = '../../sample/sample_AE/benign'

samples = [f for f in os.listdir(input_dir) if f.endswith(".exe")]

for sample in samples:
    print(sample)
    if '56796923842c2bdb03bbeac8654ba8688cefa410d2283ff46492325b7150acbe_SIN_COFF_OH_SAP_SAD_RH_RC_MDH_OAP_SRN_CS_EDS.exe' in sample:
        continue
    if '.ipynb' in sample:
        continue
    full_sample_path = os.path.join(input_dir, sample)  # 전체 파일 경로 생성

    mod = Modifier(full_sample_path, save_dir)
    
    for pert in perts:
        print (pert)
        eval("mod.{}()".format(pert))

# sample = "putty.exe"
# mod = Modifier(sample, "m_sample_2")

# for pert in perts:
#     print (pert)
#     eval("mod.{}()".format(pert))

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
