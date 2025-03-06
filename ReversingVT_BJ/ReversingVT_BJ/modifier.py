# # import util
# import os
# import sys
# import json
# import lief
# # import perturbation as p
# from multiprocessing import Pool
# from modifier import Modifier
# import random

# perts = ["modify_dos_header","dos_stub","coff_header","rich_header","optional_header",
#         "section_rename","section_add","section_append","content_shifting",
#         "jmp_overlay_back","overlay_append","instruction_change","resource_change","increase_section"]

# seed = 1

# input_dir = '/home/younghoon.ban/Dike_lable/RQ4/sample/Seed'
# save_dir =  '/home/younghoon.ban/Dike_lable/RQ4/sample/'+str(seed)


# for root, dirs, files in os.walk(input_dir):
#     for file in files:
#         pert_list = random.sample(perts,seed)
#         full_path = os.path.join(root, file)
#         rel_path = os.path.relpath(full_path, input_dir)  # 내부 구조 유지
        
#         ae_input_dir = full_path

#         ae_save_dir = os.path.join(save_dir,rel_path).replace(file,'')

#         os.makedirs(os.path.dirname(ae_save_dir), exist_ok=True)
        
#         mod = Modifier(ae_input_dir, ae_save_dir)
        
#         for pert in pert_list:
#             eval("mod.{}()".format(pert))

import os
import random
import shutil
from modifier import Modifier
import multiprocessing

cleanup_tmp = False  # ✅ True로 설정하면 모든 실행이 끝난 후 tmp 디렉토리 삭제

# 변형 기법 -> 약어 매핑
pert_abbr = {
    "modify_dos_header": "MDH",
    "extend_dos_stub": "EDS",
    "coff_header": "COFF",
    "rich_header": "RH",
    "optional_header": "OH",
    "section_rename": "SRN",
    
    "section_add": "SAD",
    "section_append": "SAP",
    
    "content_shifting": "CS",
    
    "jmp_overlay_back": "JOB"
    ,
    "overlay_append": "OAP",
    
    "instruction_change": "IC",
    "resource_change": "RC",
    "section_increase": "SIN",
}

perts = list(pert_abbr.keys())

input_dir = '/home/younghoon.ban/Dike_lable/RQ4/sample/Seed'
base_save_dir = '/home/younghoon.ban/Dike_lable/RQ4/sample/'
tmp_base_dir = '/home/younghoon.ban/Dike_lable/RQ4/tmp/perturbation_tmp/'
log_file_path = os.path.join('./', "debug_output.txt")

def log_message(message):
    print(message)
    with open(log_file_path, "a", encoding="utf-8") as log_file:
        log_file.write(message + "\n")

for seed in range(1, len(perts) + 1):
    seed_dir = os.path.join(base_save_dir, str(seed))
    os.makedirs(seed_dir, exist_ok=True)

sub_dirs = [os.path.join(input_dir, d) for d in os.listdir(input_dir) if os.path.isdir(os.path.join(input_dir, d))]

def process_directory(directory, seed):
    save_dir = os.path.join(base_save_dir, str(seed))
    tmp_dir = os.path.join(tmp_base_dir, str(seed))
    os.makedirs(tmp_dir, exist_ok=True)

    for root, _, files in os.walk(directory):
        for file in files:
            #if 'f71702e5b7fb4c55cdb2348a253ab4df6adfa84acd18e7ccc7b252495550a9a8' not in file:
                #continue

            pert_list = random.sample(perts, seed)
            pert_abbr_list = [pert_abbr[pert] for pert in pert_list]
            full_path = os.path.join(root, file)
            rel_path = os.path.relpath(full_path, input_dir)

            prev_file = full_path  
            log_message(f"🔹 [seed={seed}] 변형 대상: {prev_file}, 선택된 변형: {pert_list}")

            modified_file_keys = []  # 🔥 변형된 파일명을 저장할 리스트
            for i, pert in enumerate(pert_list):
                file_name, file_ext = os.path.splitext(os.path.basename(prev_file))
                
                # 🔥 약어만 저장된 파일명으로 변형
                modified_file_keys.append(pert_abbr[pert])
                short_file_name = f"{file_name.split('|')[0]}|{'_'.join(modified_file_keys)}{file_ext}"

                tmp_save_dir = os.path.join(tmp_dir, os.path.dirname(rel_path))
                os.makedirs(tmp_save_dir, exist_ok=True)

                final_save_dir = os.path.join(save_dir, os.path.dirname(rel_path))
                tmp_save_file = os.path.join(tmp_save_dir, f"{file_name}|{pert}{file_ext}")  # 🔥 기존 긴 파일명
                short_tmp_save_file = os.path.join(tmp_save_dir, short_file_name)  # 🔥 짧은 파일명 적용

                log_message(f"input dir : {prev_file}")
                log_message(f"save dir :  {tmp_save_file} (변형 후)")
                log_message(f"modified_file_name : {short_file_name} (최종 변경 파일명)")

                # 🔥 Modifier 실행
                mod = Modifier(prev_file, tmp_save_dir)
                eval(f"mod.{pert}()")

                # 🔥 변형 후 파일명을 변경
                if os.path.exists(tmp_save_file):
                    os.rename(tmp_save_file, short_tmp_save_file)
                    log_message(f"🔄 파일명 변경: {tmp_save_file} -> {short_tmp_save_file}")
                else:
                    log_message(f"❌ [ERROR] 변형된 파일이 존재하지 않음: {tmp_save_file}")
                    return  

                log_message(f"✅ [seed={seed}] {prev_file} -> {short_tmp_save_file} ({pert}) 변형 완료")

                prev_file = short_tmp_save_file  

            # 🔥 최종 저장할 때도 **짧은 파일명 유지**
            final_save_file = os.path.join(final_save_dir, short_file_name)

            os.makedirs(final_save_dir, exist_ok=True)

            if os.path.exists(prev_file):
                shutil.move(prev_file, final_save_file)
                log_message(f"🚀 [seed={seed}] 최종 파일 이동: {prev_file} -> {final_save_file}")
            else:
                log_message(f"❌ [ERROR] 최종 변형 파일이 존재하지 않음: {prev_file}")

if __name__ == "__main__":
    num_workers = min(len(sub_dirs), multiprocessing.cpu_count())  

    if os.path.exists(log_file_path):
        os.remove(log_file_path)

    with multiprocessing.Pool(num_workers) as pool:
        pool.starmap(process_directory, [(d, seed) for seed in range(1, len(perts) + 1) for d in sub_dirs])

#     for seed in range(1, len(perts) + 1):
#         for d in sub_dirs:
#             process_directory(d, seed)  # 🔥 멀티프로세싱 없이 실행

    log_message("\n✅ [ALL SEEDS DONE] 모든 Seed 처리 완료!")

    # ✅ cleanup_tmp=True일 때만 tmp 디렉토리 삭제
    if cleanup_tmp and os.path.exists(tmp_base_dir):
        shutil.rmtree(tmp_base_dir)
        log_message(f"\n🧹 [CLEANUP] 모든 tmp 디렉토리 삭제 완료: {tmp_base_dir}\n")