import os
import time
import json
from vtapi3 import VirusTotalAPIFiles, VirusTotalAPIError
import sys

API_KEY = sys.argv[1]  # 쉘 스크립트에서 전달된 API 키
request_count = 0  # 현재 API 키의 요청 횟수

def initialize_vt_files(api_key):
    return VirusTotalAPIFiles(api_key)

def VT_report(file_hash, save_file_path, vt_files):
    global request_count

    # 디렉토리가 없으면 생성
    save_dir = os.path.dirname(save_file_path)
    if not os.path.exists(save_dir):
        os.makedirs(save_dir)

    while request_count < 500:  # 요청 횟수가 500개 미만인 동안만 실행
        try:
            # 해시값을 사용하여 리포트 요청
            result = vt_files.get_report(file_hash)
            request_count += 1  # 요청이 성공하면 요청 횟수 증가

            # 할당량 초과 메시지 확인
            if b'"message": "Quota exceeded"' in result:
                print(f"Quota exceeded for {file_hash}. Exiting program.")
                time.sleep(3600)
                sys.exit(0)  # 프로그램 종료

            # 리포트를 JSON 형식으로 저장
            result = json.loads(result)
            with open(save_file_path, 'w') as f:
                json.dump(result, f)

            print(f"Saved VT report for {file_hash} at {save_file_path}")
            time.sleep(15)  # 실제로 요청이 성공적으로 이루어진 후에만 대기
            break  # 성공적으로 저장되면 while 루프 종료

        except VirusTotalAPIError as err:
            if err.err_code == 429:  # 할당량 초과 오류일 경우 종료
                print(f"Error 429 for {file_hash}. Exiting program.")
                sys.exit(0)
            elif err.err_code == 413:
                print(f"Error 413 for {file_hash}. Exiting program.")
                sys.exit(0)
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
                pass
                #print(f"Report already exists for {file_hash}, skipping...")
        except json.JSONDecodeError:
            print(f"Corrupted JSON found for {file_hash}. Deleting and re-fetching...")
            os.remove(save_file_path)
            VT_report(file_hash, save_file_path, vt_files)
    else:
        # 리포트가 없으면 새로 요청
        VT_report(file_hash, save_file_path, vt_files)

def traverse_and_report(save_root_dir):
    vt_files = initialize_vt_files(API_KEY)  # 전달된 API 키로 VirusTotal API 설정
    
    with open('./yh_files.txt', 'r') as file:
        lines = file.readlines()
        #print(lines)

    # 각 해시 값에 대해 리포트 요청
    for file_hash in lines:
        if request_count >= 500:
            print("Reached 500 requests. Exiting program.")
            sys.exit(0)
        file_hash = file_hash.strip()  # 줄 끝의 개행문자 제거
        save_file_path = os.path.join(save_root_dir, f"{file_hash}.json")

        # JSON 파일 확인 및 리포트 요청
        check_and_retrieve_report(file_hash, save_file_path, vt_files)

save_root_directory = '../VS_2024/report/'  # JSON 리포트가 저장될 루트 디렉토리

# 디렉토리를 순회하며 VT 리포트를 생성하고 저장
traverse_and_report(save_root_directory)
