import shutil
import os
import subprocess
import pefile
import re
from collections import Counter
import statistics
import pandas as pd

def search_type(label):
    #print(label)
    #label = 'BC.Win.Virus.Ransom-9157.A'
    if 'BC.' in label:
        #label = label.replace('.A','')
        return 'BYTECODE'
        
    result = subprocess.check_output(f'sigtool --find-sigs="{label}"', shell=True)
    sig = result.decode('utf-8')  # 바이트 값을 문자열로 변환
    sig = sig.strip().splitlines()
    
    #print(sig)

    
    #print(sig)
    if len(sig)>1:
        try:
            index = [i for i, item in enumerate(sig) if label == item.split(':')[-1]] 
            sig = sig[index[0]]
        except IndexError:
            index = [i for i, item in enumerate(sig) if label == item.split(':')[0].split(' ')[-1]]
            sig = sig[index[0]]
    else:
        try:
            sig = sig[-1]
        except IndexError:
            sig = 'None'
    #print("return sig : ",sig)
    #asdf()
    return sig

def process_line(line):

    if '/home/younghoon.ban/' not in line:
        return
    
    line = line.split('/')[-1]
    line = line.replace('_changing','')
    line = line.split(':')
    sample = line[0]
    label = line[-1].replace(' FOUND','')

    return sample, label.strip()

def compare_files(file1, file2):
    # 파일 읽기
    bypassing_cnt = 0
    change_label_cnt = 0
    fam_change_cnt = 0
    same_fam_change_number_cnt = 0
    
    bypassing_fam_list=[]
    bypassing_sig_type=[]
    
    change_fam_list=[]
    change_sig_type=[]
    
    my_dict = {"fam": [], "type": [], "cnt": []}
    
    with open(file1, 'r') as f1:
        lines1 = [process_line(line) for line in f1]  # 첫 번째 파일의 줄을 가공 후 집합으로 저장
        lines1 = [item for item in lines1 if item is not None]
        lines1 = dict(lines1)
        
    with open(file2, 'r') as f2:
        lines2 = set(process_line(line) for line in f2)  # 두 번째 파일의 줄을 가공 후 집합으로 저장
        lines2 = [item for item in lines2 if item is not None]
        lines2 = dict(lines2)
    
    #print(lines1, type(lines1))
    
    for sample, label in lines1.items():
        sig_label = label
        label = label.lower()

        if 'ok' in label:
            continue
            
#         sig = search_type(sig_label)
#         sig_type = sig.split(' ')[0]
#         print()
            
        ae_label = lines2[sample]
        ae_sig_label = ae_label
        ae_label = ae_label.lower()
        
        
        if 'ok' in ae_label:
            bypassing_cnt+=1
#             label = label.split('.')[-1].split('-',1)[0]
#             bypassing_fam_list.append(label)
#             sig = search_type(sig_label)
#             sig_type = sig.split(' ')[0]
#             bypassing_sig_type.append(sig_type)
            continue
            
        if label !=ae_label:
            change_label_cnt+=1
            #continue
            
            seed_fam = label.split('-')[0]
            seed_fam_num = label.split('-',1)[-1]
            
            ae_fam = ae_label.split('-')[0]
            ae_fam_num = ae_label.split('-',1)[-1]
            
            if seed_fam != ae_fam:
                fam_change_cnt+=1
                
                change_fam = seed_fam +' -> '+ae_fam
#                 label = label.split('.')[-1].split('-',1)[0]
#                 sig = search_type(sig_label)
#                 sig_type = sig.split(' ')[0]
                
#                 ae_label = ae_label.split('.')[-1].split('-',1)[0]
#                 ae_sig = search_type(ae_sig_label)
#                 ae_sig_type = ae_sig.split(' ')[0]
                
                print(change_fam)
                print("   ",ae_sig_label)
                
                if change_fam in my_dict['fam']:
                    index = my_dict['fam'].index(change_fam)
                    my_dict['cnt'][index] += 1
                    
                else:
                    my_dict['fam'].append(change_fam)
                    my_dict['cnt'].append(1)
                    label = label.split('.')[-1].split('-',1)[0]
                    sig = search_type(sig_label)
                    sig_type = sig.split(' ')[0]

                    ae_label = ae_label.split('.')[-1].split('-',1)[0]
                    ae_sig = search_type(ae_sig_label)
                    ae_sig_type = ae_sig.split(' ')[0]
                    my_dict['type'].append(sig_type+' -> '+ae_sig_type)
                    
                    
                #print("  ",sig_type, ae_sig_type)
                
                #change_fam_list.append()
                #change_sig_type.append()
                continue

            if  seed_fam == ae_fam and seed_fam_num!=ae_fam_num:
                same_fam_change_number_cnt+=1
                continue
                
           
    print("bypassing_cnt : ",bypassing_cnt)       
    print("change_label_cnt : ",change_label_cnt)       
    print("fam_change_cnt : ",fam_change_cnt)       
    print("same_fam_change_number_cnt : ",same_fam_change_number_cnt)    
    print(Counter(bypassing_fam_list), len(Counter(bypassing_fam_list)))
    print(Counter(bypassing_sig_type), len(Counter(bypassing_sig_type)))
    print(my_dict)
    
    df = pd.DataFrame(my_dict)

    # CSV 파일로 저장
    df.to_csv("./resource_change.csv", index=False)

    #print("CSV 파일로 저장 완료!")



# 파일 경로 설정
file1_path = '../malware.txt'
#file2_path = '../sample/perturbated_labling_sample/instruction_change.txt'    
file2_path = '../sample/perturbated_labling_sample/resource_change.txt'    
#file2_path = '../sample/perturbated_labling_sample/instruction_change+resource_change.txt'    

# 비교 실행
compare_files(file1_path, file2_path)

