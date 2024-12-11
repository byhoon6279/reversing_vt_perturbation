import os
import time
import json
from vtapi3 import VirusTotalAPIFiles, VirusTotalAPIError

# 사용할 API 키들을 리스트에 저장
API_KEYS = [
    'ac3b05e11b4f2545fc806868bb59f2543f26f3c66d021d7bc4cb697228fd5b55', #naver
    '2732d0d5012bf3d61d8f7e8060fdd3319ec6d784c3138e9ec3b7c10f95999458', #ssu
    '6f1d52c9a1932e250b6b26615e050504ce16232021e625b8c015203c6db87c35', #google
    'f7d55da77fce83f5851cbea25d8c0a0b1089c1afd53d55a856b0255b54791c12', #kakao
    # 필요한 만큼 추가
]
current_key_index = 0  # 현재 API 키 인덱스
request_count = 0  # 현재 API 키의 요청 횟수

def initialize_vt_files():
    global current_key_index
    return VirusTotalAPIFiles(API_KEYS[current_key_index])

def switch_api_key():
    global current_key_index, request_count
    current_key_index = (current_key_index + 1) % len(API_KEYS)
    request_count = 0  # 새 키로 전환 시 요청 횟수 초기화
    print(f"Switching to new API key. Now using API key {current_key_index + 1}/{len(API_KEYS)}")
    return initialize_vt_files()

def VT_report(file_hash, save_file_path, vt_files):
    global request_count
    
    # 디렉토리가 없으면 생성
    save_dir = os.path.dirname(save_file_path)
    if not os.path.exists(save_dir):
        os.makedirs(save_dir)

    while True:
        try:
            # 현재 키의 요청 횟수가 500을 넘으면 API 키를 변경
            if request_count >= 500:
                vt_files = switch_api_key()

            # 해시값을 사용하여 리포트 요청
            result = vt_files.get_report(file_hash)
            request_count += 1  # 요청이 성공하면 요청 횟수 증가
            
            # QuotaExceededError 메시지 확인
            #if b'"QuotaExceededError"' in result:
            if b'"message": "Quota exceeded"' in result:
                print(f"Quota exceeded unexpectedly for {file_hash}. Switching API key.")
                vt_files = switch_api_key()
                continue  # 키를 바꾸고 다시 시도

            # 리포트를 JSON 형식으로 저장
            result = json.loads(result)
            with open(save_file_path, 'w') as f:
                json.dump(result, f)

            print(f"Saved VT report for {file_hash} at {save_file_path}")
            time.sleep(15)  # 실제로 요청이 성공적으로 이루어진 후에만 대기
            break  # 성공적으로 저장되면 while 루프 종료

        except VirusTotalAPIError as err:
            if err.err_code == 429:  # 할당량 초과 오류일 경우 API 키 변경
                print(f"Error 429 for {file_hash}. Switching API key.")
                vt_files = switch_api_key()
            elif err.err_code == 413:
                print(f"Error 413 for {file_hash}. Switching API key.")
                vt_files = switch_api_key()
            else:
                print(f"Error fetching report for {file_hash}: {err} (Code: {err.err_code})")
            break
        except json.JSONDecodeError as jde:
            print(f"Error decoding JSON for {file_hash}: {jde}")
            break

def check_and_retrieve_report(file_hash, save_file_path, vt_files):
    # JSON 리포트가 이미 있는 경우 오류가 포함되었는지 확인
    if os.path.exists(save_file_path):
        try:
            with open(save_file_path, 'r') as f:
                ori_json = json.load(f)
            # JSON 파일에 오류가 있는지 확인
            if "error" in ori_json:
                print(f"Error found in existing report for {file_hash}. Deleting and re-fetching...")
                os.remove(save_file_path)
                VT_report(file_hash, save_file_path, vt_files)
            else:
                print(f"Report already exists for {file_hash}, skipping...")
        except json.JSONDecodeError:
            print(f"Corrupted JSON found for {file_hash}. Deleting and re-fetching...")
            os.remove(save_file_path)
            VT_report(file_hash, save_file_path, vt_files)
    else:
        # 리포트가 없으면 새로 요청
        VT_report(file_hash, save_file_path, vt_files)

def traverse_and_report(save_root_dir):
    vt_files = initialize_vt_files()  # 초기 API 키로 VirusTotal API 설정
    
    with open('./yh_files.txt', 'r') as file:
        lines = file.readlines()
        print(lines)

    # 각 해시 값에 대해 리포트 요청
    for file_hash in lines:
        file_hash = file_hash.strip()  # 줄 끝의 개행문자 제거
        save_file_path = os.path.join(save_root_dir, f"{file_hash}.json")

        # JSON 파일 확인 및 리포트 요청
        check_and_retrieve_report(file_hash, save_file_path, vt_files)

save_root_directory = '../VS_2024/report/'  # JSON 리포트가 저장될 루트 디렉토리

# 디렉토리를 순회하며 VT 리포트를 생성하고 저장
traverse_and_report(save_root_directory)