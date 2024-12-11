import os
import json
from datetime import datetime
from collections import Counter

# .json 파일 읽기

def first_submission(directory_path):
    json_files = [file for file in os.listdir(directory_path) if file.endswith(".json")]

    date_list = []
    # 각 파일의 내용을 읽어서 저장
    for file in json_files:
        file_path = os.path.join(directory_path, file)
        with open(file_path, 'r', encoding='utf-8') as f:
            json_data = json.load(f)
        try:
            first_submission_data = json_data['data']['attributes']['first_submission_date']
            readable_date = datetime.utcfromtimestamp(first_submission_data).strftime('%Y-%m')
            date_list.append(readable_date)

        except KeyError:
            print(file)

    counted_elements = Counter(date_list)
    print(counted_elements)
    
def detection_percentage(directory_path):
    json_files = [file for file in os.listdir(directory_path) if file.endswith(".json")]

    detection_rate_list = []
    # 각 파일의 내용을 읽어서 저장
    for file in json_files:
        file_path = os.path.join(directory_path, file)
        with open(file_path, 'r', encoding='utf-8') as f:
            json_data = json.load(f)
        try:
            last_analysis_stats = json_data['data']['attributes']['last_analysis_stats']
            
            malicious_system = json_data['data']['attributes']['last_analysis_stats']['malicious']
            total_system = sum(last_analysis_stats.values())
            detection_rate = (malicious_system/total_system)*100
            
            detection_rate_list.append(round(detection_rate))
            
        except KeyError:
            print(file)
            
    print(Counter(detection_rate_list))
    #asdf()

def make_dict(directory_path):
    json_files = [file for file in os.listdir(directory_path) if file.endswith(".json")]

    date_list = []
    detection_rate_list = []
    file_list = []
    
    m_dict={}
    # 각 파일의 내용을 읽어서 저장
    for file in json_files:
        file_path = os.path.join(directory_path, file)
        with open(file_path, 'r', encoding='utf-8') as f:
            json_data = json.load(f)
        try:
            first_submission_data = json_data['data']['attributes']['first_submission_date']
            readable_date = datetime.utcfromtimestamp(first_submission_data).strftime('%Y-%m')
            date_list.append(readable_date)
            
            last_analysis_stats = json_data['data']['attributes']['last_analysis_stats']
            
            malicious_system = json_data['data']['attributes']['last_analysis_stats']['malicious']
            total_system = sum(last_analysis_stats.values())
            detection_rate = (malicious_system/total_system)*100
            
            detection_rate_list.append(round(detection_rate))
            
            file_list.append(file)

        except KeyError:
            print(file)
    m_dict = {'file':file_list, 'detection_rate':detection_rate_list, 'first_submission_data':date_list}
        
    return m_dict

def sort_m_dict(m_dict):
    # 데이터를 리스트로 재구성
    data = [
        {
            'file': m_dict['file'][i],
            'detection_rate': m_dict['detection_rate'][i],
            'first_submission_data': m_dict['first_submission_data'][i]
        }
        for i in range(len(m_dict['file']))
    ]

    # 탐지율 높은 순 -> 제출일 최신 순으로 정렬
    sorted_data = sorted(
        data,
        key=lambda x: (-x['detection_rate'], x['first_submission_data']),
    )

    # 정렬된 데이터를 다시 m_dict 형식으로 변환
    sorted_m_dict = {
        'file': [item['file'] for item in sorted_data],
        'detection_rate': [item['detection_rate'] for item in sorted_data],
        'first_submission_data': [item['first_submission_data'] for item in sorted_data],
    }

    return sorted_m_dict

def search_mal_name(directory_path):
    json_files = [file for file in os.listdir(directory_path) if file.endswith(".json")]
    
    mal_name_list=[]
    
    # 각 파일의 내용을 읽어서 저장
    for file in json_files:
        file_path = os.path.join(directory_path, file)
        with open(file_path, 'r', encoding='utf-8') as f:
            json_data = json.load(f)
        try:
            label = json_data['data']['attributes']['popular_threat_classification']['suggested_threat_label']
            #print(label)
            #readable_date = datetime.utcfromtimestamp(first_submission_data).strftime('%Y-%m')
            mal_name_list.append(label)
            
        except KeyError:
            try:
                label = json_data['data']['attributes']['meaningful_name']
                mal_name_list.append(label)
            except KeyError:
                print(file)
            
   # m_dict = {'file':file_list, 'detection_rate':detection_rate_list, 'first_submission_data':date_list}
        
    print(Counter(mal_name_list))
    
def main():
    # 경로 설정
    directory_path = "../VS_2024/report/"
    #first_submission(directory_path)
    #detection_percentage(directory_path)
    
#     m_dict = make_dict(directory_path)
#     m_dict = sort_m_dict(m_dict)
#     print(type(m_dict))
#     for file, detection_rate, date in zip(m_dict['file'][:100],  m_dict['detection_rate'][:100], m_dict['first_submission_data'][:100]):
#         print(file, detection_rate, date)

    search_mal_name(directory_path)

    
if __name__ == '__main__':
    main()