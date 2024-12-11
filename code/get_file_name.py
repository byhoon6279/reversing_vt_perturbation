import os

def list_all_files(home_directory):
    file_names = []
    for root, dirs, files in os.walk(home_directory):
        print(root)
        for file in files:
            file_names.append(file)  # 파일 이름을 리스트에 추가
    return file_names

# 사용 예시
home_directory = "/hdd3/younghoon_pe_malware_32bit/2024/"  # 여기에 홈 디렉토리 경로를 지정하세요
all_files = list_all_files(home_directory)

# 결과 출력
print()
half = int(len(all_files)/2)

jbj=[]
yh=[]
for cnt,file_name in enumerate(all_files):
    file_name = file_name.replace('VirusShare_','')
    print(file_name)
    
    if cnt < half:
        yh.append(file_name)
    else:
        jbj.append(file_name)
        
print(len(jbj))
print(len(yh))

# jbj와 yh 리스트를 텍스트 파일로 저장
with open("./VirusShare2024_files_24574.txt", "w") as jbj_file:
    for file_name in jbj:
        jbj_file.write(file_name + "\n")

with open("./yh_files.txt", "w") as yh_file:
    for file_name in yh:
        yh_file.write(file_name + "\n")