import os
import shutil
import itertools
import argparse
from modifier import Modifier
import multiprocessing

# perturbation 리스트
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
    "jmp_overlay_back": "JOB",
    "overlay_append": "OAP",
    "resource_change": "RC",
    "section_increase": "SIN",
    "instruction_change": "IC"
}

perts = list(pert_abbr.keys())

# perturbation 조합 생성 (2개 ~ 14개)
#all_combinations = {i: list(itertools.combinations(perts, i)) for i in range(2, 15)}

def log_message(message, log_file_path):
    print(message)
    with open(log_file_path, "a", encoding="utf-8") as log_file:
        log_file.write(message + "\n")

def process_directory(directory, num, pert_list, input_dir, base_save_dir, tmp_base_dir, log_file_path):
    save_dir = os.path.join(base_save_dir, f"{num}_perts")
    tmp_dir = os.path.join(tmp_base_dir, f"{num}_perts")
    os.makedirs(tmp_dir, exist_ok=True)
    
    for root, _, files in os.walk(directory):
        for file in files:
            full_path = os.path.join(root, file)
            rel_path = os.path.relpath(full_path, input_dir)

            prev_file = full_path
            pert_abbr_list = [pert_abbr[pert] for pert in pert_list]
            modified_file_keys = []

            log_message(f"\n🔹 [num={num}] 변형 대상: {prev_file}, 선택된 변형: {pert_list}", log_file_path)

            for i, pert in enumerate(pert_list):
                file_name, file_ext = os.path.splitext(os.path.basename(prev_file))
                modified_file_keys.append(pert_abbr[pert])
                short_file_name = f"{file_name.split('|')[0]}|{'_'.join(modified_file_keys)}{file_ext}"

                tmp_save_dir = os.path.join(tmp_dir, os.path.dirname(rel_path))
                os.makedirs(tmp_save_dir, exist_ok=True)

                final_save_dir = os.path.join(save_dir, os.path.dirname(rel_path))
                tmp_save_file = os.path.join(tmp_save_dir, f"{file_name}|{pert}{file_ext}")
                short_tmp_save_file = os.path.join(tmp_save_dir, short_file_name)

                log_message(f"input dir : {prev_file}", log_file_path)
                log_message(f"save dir :  {tmp_save_file} (변형 후)", log_file_path)
                log_message(f"modified_file_name : {short_file_name} (최종 변경 파일명)", log_file_path)

                mod = Modifier(prev_file, tmp_save_dir)
                eval(f"mod.{pert}()")

                if os.path.exists(tmp_save_file):
                    os.rename(tmp_save_file, short_tmp_save_file)
                    log_message(f"🔄 파일명 변경: {tmp_save_file} -> {short_tmp_save_file}", log_file_path)
                else:
                    log_message(f"❌ [ERROR] 변형된 파일이 존재하지 않음: {tmp_save_file}", log_file_path)
                    return

                log_message(f"✅ [num={num}] {prev_file} -> {short_tmp_save_file} ({pert}) 변형 완료", log_file_path)
                prev_file = short_tmp_save_file

            final_save_file = os.path.join(final_save_dir, short_file_name)
            os.makedirs(final_save_dir, exist_ok=True)
            shutil.move(prev_file, final_save_file)
            log_message(f"🚀 [num={num}] 최종 파일 이동: {prev_file} -> {final_save_file}", log_file_path)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Batch perturbation script")
    parser.add_argument("-i", "--input", required=True, help="Input base directory")
    parser.add_argument("-o", "--output", help="Output directory (default: same as input)")
    parser.add_argument("-l", "--log", default="debug_output.txt", help="Log file path")
    parser.add_argument("--cleanup", action="store_true", default=True, help="Delete temporary directory after execution")
    parser.add_argument("-j", "--jobs", type=int, default=None, help="Number of parallel jobs (default: half of CPU cores)")
    args = parser.parse_args()

    input_dir = args.input
    base_save_dir = args.output if args.output else input_dir
    os.makedirs(base_save_dir, exist_ok=True)
    tmp_base_dir = os.path.join(os.path.dirname(os.path.abspath(input_dir)), "tmp", "perturbation_tmp")
    log_file_path = args.log
    cleanup_tmp = args.cleanup

    if os.path.exists(log_file_path):
        os.remove(log_file_path)

    # ✅ 기존 tmp 디렉토리 있으면 삭제
    if os.path.exists(tmp_base_dir):
        shutil.rmtree(tmp_base_dir)

    sub_dirs = [os.path.join(input_dir, d) for d in os.listdir(input_dir) if os.path.isdir(os.path.join(input_dir, d))]

    cpu_half = max(1, multiprocessing.cpu_count() // 2)
    num_workers = args.jobs if args.jobs else min(len(sub_dirs), cpu_half)

    with multiprocessing.Pool(num_workers) as pool:
        pool.starmap(
            process_directory,
            [(d, len(pert_abbr), list(pert_abbr.keys()), input_dir, base_save_dir, tmp_base_dir, log_file_path)
             for d in sub_dirs]
        )
#         pool.starmap(
#             process_directory,
#             [(d, num, pert_list, input_dir, base_save_dir, tmp_base_dir, log_file_path)
#              for num in range(2, 15) for pert_list in all_combinations[num] for d in sub_dirs]
#         )

    log_message("\n✅ [ALL PERTURBATION COMBINATIONS DONE] 모든 조합 완료!", log_file_path)

    if cleanup_tmp and os.path.exists(tmp_base_dir):
        shutil.rmtree(tmp_base_dir)
        log_message(f"\n🧹 [CLEANUP] 모든 tmp 디렉토리 삭제 완료: {tmp_base_dir}\n", log_file_path)
        
#python RQ2_modifier.py -i ~/Dike_lable/label_test/ -o ~/Dike_lable/ -o ~/Dike_lable/RQ2