import os
import shutil

# 디렉터리 경로 설정
benign_dir = '../evaluation/VT_thorw_sample/benign'
dir1 = '../sample/benign_AE/instruction_change/'
dir2 = '../sample/benign_AE/resource_change/'

resource_change_dir = '../evaluation/VT_thorw_sample/benign_AE/resource_change'
instruction_change_dir = '../evaluation/VT_thorw_sample/benign_AE/instruction_change'

# resource_change 및 instruction_change 디렉터리가 없는 경우 생성
os.makedirs(resource_change_dir, exist_ok=True)
os.makedirs(instruction_change_dir, exist_ok=True)

# benign_dir의 파일 목록을 가져옴
benign_files = set(os.listdir(benign_dir))

# dir1과 dir2에서 benign 파일과 동일한 파일을 찾아서 복사
for src_dir, dest_dir in [(dir1, instruction_change_dir), (dir2, resource_change_dir)]:
    for filename in os.listdir(src_dir):
        # `_changing.exe`가 붙은 경우 제거하고 비교
        original_name = filename.replace('_changing.exe', '.exe')
        if original_name in benign_files:
            src_path = os.path.join(src_dir, filename)
            dest_path = os.path.join(dest_dir, filename)
            shutil.copy2(src_path, dest_path)
            print(f"Copied {filename} from {src_dir} to {dest_dir}")

print("복사 작업 완료")