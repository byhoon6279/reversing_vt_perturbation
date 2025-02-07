# -*- coding: utf-8 -*- 
import glob
import os
import subprocess
import json
from multiprocessing import Pool, Process, Value, Lock, cpu_count
import glob
import hydra
import omegaconf
from omegaconf import DictConfig
import argparse
from pathlib import Path
p = Path(os.path.abspath(__file__))
base_path = str(p.parents[3])

def get_data(filename):
    with open(filename, 'r') as f:
        data = f.readline()
        data_list = json.loads(data.strip())
    f.close()
    return data_list

def obtain_call_addr(cmd):
    p = subprocess.Popen(cmd, shell=True)
    p.wait()

def main(example_path):
    print("base_path : ",base_path)
    cfg_path = os.path.join(base_path, "./configs/preprocess.yaml")
    config = omegaconf.OmegaConf.load(cfg_path)
    
    IDA_PATH = config.IDA_PATH
    SCRIPT_PATH = os.path.join(base_path, config.SCRIPT_PATH)
    cmd = IDA_PATH + ' -c -A -S' + SCRIPT_PATH + ' ' + example_path
    print("run command: ", cmd)
    obtain_call_addr(cmd)
    
# # 디렉토리 내 모든 파일을 재귀적으로 탐색하는 함수
# def process_directory(directory):
#     directory = Path(directory)
    
#     # 모든 파일을 재귀적으로 탐색
#     for file_path in directory.rglob('*'):
#         if file_path.is_file():
#             print(f"Processing file: {file_path}")
#             try:
#                 # 각 파일에 대해 main 함수 실행
#                 main(str(file_path))  # example_path로 파일 경로 전달
#             except Exception as e:
#                 print(f"Error processing {file_path}: {e}")
                
# 각 파일을 처리하는 함수
def process_file(file_path):
    try:
        print(f"Processing file: {file_path}")
        main(str(file_path))  # main 함수에 파일 경로 전달
    except Exception as e:
        print(f"Error processing {file_path}: {e}")
        
def process_directory(directory):
    directory = Path(directory)
    
    # 모든 파일을 재귀적으로 탐색하고, 멀티프로세싱으로 처리
    files = [file_path for file_path in directory.rglob('*') if file_path.is_file()]
    
    # 멀티프로세싱으로 파일 처리
    with Pool(processes=int(cpu_count()/4)) as pool:  # 시스템의 CPU 코어 수만큼 프로세스를 생성
        pool.map(process_file, files)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', default = '', type = str, dest = 'filename')
#     parser.add_argument('-d', default='', type=str, dest='directory', help="디렉토리 경로를 입력하세요.")
    args = parser.parse_args()
#     directory_path = args.directory  # 사용자로부터 디렉토리 경로 입력받음
#     process_directory(directory_path)  # 디렉토리 내 파일 처리
    
    #parser.add_argument('-f', default = '', type = str, dest = 'filename')
    example_path = args.filename
    main(example_path)
