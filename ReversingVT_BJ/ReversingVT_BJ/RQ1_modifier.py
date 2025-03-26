import os
import argparse
import lief
from modifier import Modifier
from multiprocessing import Pool, cpu_count

# perturbation 리스트
perts = [
    "modify_dos_header", "extend_dos_stub", "coff_header", "rich_header", "optional_header",
    "section_rename", "section_add", "section_append", "content_shifting",
    "jmp_overlay_back", "overlay_append", "instruction_change", "resource_change", "section_increase"
]

# perturbation 실행 함수
def process_sample(sample_path_and_savedir):
    sample_path, save_dir = sample_path_and_savedir
    sample = os.path.basename(sample_path)
    print(f"[+] Processing: {sample}")

    try:
        mod = Modifier(sample_path, save_dir)
        for pert in perts:
            try:
                eval(f"mod.{pert}()")
            except Exception as e:
                print(f"[!] Error in {pert} for {sample}: {e}")
    except Exception as e:
        print(f"[!] Failed to process {sample}: {e}")

# ✅ argparse 설정
parser = argparse.ArgumentParser(description="Perturb executable samples with various methods.")
parser.add_argument("-i", "--input", required=True, help="Path to input directory containing .exe files")
parser.add_argument("-o", "--output", required=True, help="Path to directory where modified samples will be saved")
parser.add_argument("--multi", action="store_true", help="Enable multiprocessing (default: off)")
parser.add_argument("-j", "--jobs", type=int, default=cpu_count(), help="Number of parallel processes (used only if --multi is set)")

args = parser.parse_args()
input_dir = args.input
save_dir = args.output
use_multi = args.multi
num_jobs = args.jobs

sample_paths = []
for root, dirs, files in os.walk(input_dir):
    for file in files:
        if file.endswith(".exe"):
            full_path = os.path.join(root, file)
            sample_paths.append((full_path, save_dir))

# ✅ 메인 실행
if __name__ == '__main__':
    if use_multi:
        print(f"[*] Running with multiprocessing (jobs={num_jobs})")
        with Pool(processes=num_jobs) as pool:
            pool.map(process_sample, sample_paths)
    else:
        print("[*] Running sequentially (no multiprocessing)")
        for pair in sample_paths:
            process_sample(pair)

            # python RQ1_modifier.py -i ./input -o ./m_sample_2