#benign
import os
import random
import shutil

def sample_and_copy_files(source_directory, destination_directory, sample_size):
    # 디렉터리 내 파일 목록 가져오기
    all_files = [f for f in os.listdir(source_directory) if os.path.isfile(os.path.join(source_directory, f))]

    # 파일이 sample_size 미만일 경우를 고려하여 샘플링 크기 조정
    actual_sample_size = min(sample_size, len(all_files))

    # 랜덤하게 sample_size만큼 파일 샘플링
    sampled_files = random.sample(all_files, actual_sample_size)
    
    # 목적지 디렉터리가 없으면 생성
    os.makedirs(destination_directory, exist_ok=True)

    # 샘플링된 파일 복사
    for file_name in sampled_files:
        source_file_path = os.path.join(source_directory, file_name)
        shutil.copy(source_file_path, destination_directory)
        print(f"{source_file_path} -> {destination_directory} 복사 완료")

    return sampled_files

def copy_matching_files(sampled_files, source_directory, destination_directory, sample_size):
    # 존재하지 않는 파일을 저장할 리스트
    missing_files = []
    
    # 목적지 디렉터리가 없으면 생성
    os.makedirs(destination_directory, exist_ok=True)

    # 샘플링된 파일 이름을 기준으로 source_directory에서 destination_directory로 복사
    for file_name in sampled_files:
        changing_file_name = file_name.replace('.exe','_changing.exe')
        source_file_path = os.path.join(source_directory, changing_file_name)
        if os.path.exists(source_file_path):
            shutil.copy(source_file_path, destination_directory)
            print(f"{source_file_path} -> {destination_directory} 복사 완료")
        else:
            print(f"{changing_file_name}이(가) {source_directory}에 존재하지 않음. 건너뛴다.")
            missing_files.append(file_name)  # 존재하지 않는 파일을 추가

    # 부족한 수를 다시 샘플링하여 복사
    while len(missing_files) > 0:
        # 새로 샘플링할 파일 수
        additional_sample_size = len(missing_files)
        
        # source_directory에서 새로운 파일 샘플링
        additional_files = sample_and_copy_files(dike_benign_directory, dir1_directory, additional_sample_size)
        
        # 중복되지 않는 새 샘플링 파일 추가
        for additional_file in additional_files:
            if additional_file not in sampled_files:
                sampled_files.append(additional_file)
                
        # 재확인 및 복사
        missing_files = []
        for file_name in additional_files:
            changing_file_name = file_name.replace('.exe','_changing.exe')
            source_file_path = os.path.join(source_directory, changing_file_name)
            if os.path.exists(source_file_path):
                shutil.copy(source_file_path, destination_directory)
                print(f"{source_file_path} -> {destination_directory} 복사 완료")
            else:
                print(f"{changing_file_name}이(가) {source_directory}에 여전히 존재하지 않음.")
                missing_files.append(file_name)

# 경로 설정
# dike_benign_directory = "../sample/Dike_benign/"
# dir1_directory = "../evaluation/VT_thorw_sample/benign/"
# source_directory = "../sample/benign_AE/instruction_change+resource_change/"
# destination_directory = "../evaluation/VT_thorw_sample/benign_AE/"
sample_size = 250

dike_benign_directory = "../sample/Dike_malware/"
dir1_directory = "../evaluation/VT_thorw_sample/benign/"
source_directory = "../sample/benign_AE/instruction_change+resource_change/"
destination_directory = "../evaluation/VT_thorw_sample/benign_AE/"

# 1단계: Dike_benign에서 250개 샘플링하여 dir1_directory로 복사
sampled_files = sample_and_copy_files(dike_benign_directory, dir1_directory, sample_size)

# 2단계: 동일한 파일을 source_directory에서 찾아 destination_directory로 복사
copy_matching_files(sampled_files, source_directory, destination_directory, sample_size)

print("모든 파일 복사가 완료되었습니다.")

#malware
# def sample_and_copy_files(source_directory, destination_directory, sample_size):
#     # 모든 하위 디렉터리를 포함하여 파일 목록 가져오기
#     all_files = []
#     for root, _, files in os.walk(source_directory):
#         for file in files:
#             all_files.append(os.path.join(root, file))

#     # 파일이 sample_size 미만일 경우를 고려하여 샘플링 크기 조정
#     actual_sample_size = min(sample_size, len(all_files))

#     # 랜덤하게 sample_size만큼 파일 샘플링
#     sampled_files = random.sample(all_files, actual_sample_size)

#     # 목적지 디렉터리가 없으면 생성
#     os.makedirs(destination_directory, exist_ok=True)

#     # 샘플링된 파일 복사
#     for file_path in sampled_files:
#         # 원본 파일의 상대 경로를 유지하여 복사
#         relative_path = os.path.relpath(file_path, source_directory)
#         destination_path = os.path.join(destination_directory, relative_path)

#         # 하위 디렉터리를 포함하여 생성
#         os.makedirs(os.path.dirname(destination_path), exist_ok=True)
        
#         # 파일 복사
#         shutil.copy(file_path, destination_path)
#         print(f"{file_path} -> {destination_path} 복사 완료")

#     print(f"{actual_sample_size}개의 파일이 복사되었습니다.")

# # 샘플링할 디렉터리 경로와 복사할 디렉터리 경로 설정
# source_directory = "../sample/Dike_benign/"
# destination_directory = "../evaluation/VT_thorw_sample/benign/"
# sample_size = 500

# sample_and_copy_files(source_directory, destination_directory, sample_size)