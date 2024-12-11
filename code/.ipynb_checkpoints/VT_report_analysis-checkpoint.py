import os
import json
from datetime import datetime
from collections import Counter
import pandas as pd

# .json 파일 읽기

def first_submission(directory_path):
    common_set = [
        "Cylance", "ALYac", "Antiy-AVL", "Sophos", "Tencent", "Alibaba", 
        "AhnLab-V3", "ClamAV", "Sangfor", "K7AntiVirus", "K7GW", "Avira", 
        "Microsoft", "ESET-NOD32", "NANO-Antivirus", "VBA32", "DrWeb", 
        "Fortinet", "Zillya", "AVG", "Avast", "CAT-QuickHeal", 
        "TrendMicro-HouseCall", "Webroot", "TrendMicro", "ViRobot", 
        "F-Secure", "Yandex", "Varist", "SUPERAntiSpyware", "Trapmine", 
        "SentinelOne"
    ]
    category = []
    fam_list = []
    file_name = []
    undetected_rate = []
    detected_rate = []
    
    for root, dirs, files in os.walk(directory_path):
        # 각 root별 데이터를 저장
        for file in files:
            if '-checkpoint.' in file:
                continue
            if file.endswith(".json"):  # .json 파일만 처리
                file_path = os.path.join(root, file)
                # JSON 파일 읽기
                with open(file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)  # JSON 파싱
                    detection_sys = data['data']['attributes']['last_analysis_results']
                    filtered_data = {key: value for key, value in detection_sys.items() if key in common_set}
                    
                    # 카운트 및 비율 계산
                    undetected_count = sum(1 for value in filtered_data.values() if value['category'] == 'undetected')
                    detected_count = sum(1 for value in filtered_data.values() if value['category'] != 'undetected')
                    total_count = len(filtered_data)
                    try:
                        undetected_ratio = (undetected_count / total_count) * 100
                        detected_ratio = (detected_count / total_count) * 100
                    except ZeroDivisionError:
                        print(file_path)
                        

                    # 파일 정보 추출
                    cat = file_path.split('/')[-3]
                    fam = file_path.split('/')[-2]
                    f_name = file_path.split('/')[-1].replace('_changing', '')

                    # 데이터 저장
                    category.append(cat)
                    fam_list.append(fam)
                    file_name.append(f_name)
                    undetected_rate.append(f"{undetected_ratio:.2f}%")
                    detected_rate.append(f"{detected_ratio:.2f}%")
        
    data = {"Category": category,"Family": fam_list,"File Name": file_name,"Undetected Rate": undetected_rate,"Detected Rate": detected_rate}
    df = pd.DataFrame(data)
    print(f"\nDataFrame for root: {root}")
    print(df)

    # CSV 저장 (선택)
    df.to_csv("./detection_report.csv", index=False)
    #print(f"Saved DataFrame to {root.replace('/', '_')}_detection_report.csv")

    
def main():
    # 경로 설정
    directory_path = "../evaluation/RQ3/all_bypassing_report/"
    first_submission(directory_path)

    
if __name__ == '__main__':
    main()