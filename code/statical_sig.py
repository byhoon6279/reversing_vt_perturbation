import shutil
import os
import subprocess
import pefile
import re
from collections import Counter
import statistics

def sig_ratio(input_dir):
    cnt = 0
    type_list = []

    with open(input_dir, "r", encoding="utf-8") as file:
        content = file.read()
        
    content = content.split('\n')
    for line in content:
        if '[' in line and 'Win.' in line or ('--------------------------------------------------' in line):
            print(line)
        if '[' in line and 'Win.' in line:
            sig_type = line.split( )[0].split('.')[-1].replace(']','')
            type_list.append(sig_type)
            cnt+=1
            
    print(cnt)
    print(Counter(type_list))

def sig_section_ratio(input_dir):
    cnt = 0
    section_list = []
    
    with open(input_dir, "r", encoding="utf-8") as file:
        content = file.read()
    
    #mdb
    content = content.split('--------------------------------------------------')
    for line in content:
        if '.mdb' in line:
            print(line)
            lines = line.strip().split('\n')[1]
            section = lines.split(' - ')[-1]
            section_list.append(section)
    print(Counter(section_list))

#ldb, ndb
#     content = content.split('--------------------------------------------------')
    
#     for line in content:        
#         if '.ldb' in line or '.ndb' in line:
#             print(line)
#             cnt+=1
#             lines = line.strip().split('\n')
            
#             for l in lines:                
#                 if '.ldb' in l or '.ndb' in l :
#                     continue
                    
#                 sigs = l.split(' - ')
                
#                 print("sigs : ",sigs, len(sigs))
#                 section = sigs[-1].strip().lower()
#                 section_list.append(section)
            
#     print(Counter(section_list), cnt)

#total
#     content = content.split('--------------------------------------------------')
    
#     for line in content:        
#         print(line)
#         lines = line.strip().split('\n')[1:]
#         #print(lines, lines[1:])

#         for l in lines:                

#             sigs = l.split(' - ')
#             cnt+=1
#             #print("sigs : ",sigs, len(sigs))
#             section = sigs[-1].strip().lower()
# #             print(section)
#             if '.text' in section and ' @.text3' in section:
#                 print(sigs, section)
#                 asdf()
#             section_list.append(section)
            
#     print(Counter(section_list), cnt)


def ldb_sig_len(input_dir):
    sig_cnt=[]
    len_list=[]
    
    with open(input_dir, "r", encoding="utf-8") as file:
        content = file.read()

    content = content.split('--------------------------------------------------')
    
    #print(content)
    
    for i in content:
        
        if '.ldb' in i:
            #i = i.strip()
            sigs = i.split('\n')[1:]
            sig_cnt.append(len(sigs))
            for sig in sigs:
                sig = sig.split(' - ')[0].strip()
                
                if not sig:
                    continue
                
                if '::' in sig:
                    sig = sig.split('::')[0]

                len_list.append(len(sig))
                
                if len(sig) == 8:
                    print(sig)
            
    print('max sig cnt : ',max(sig_cnt))
    print('min sig cnt : ',min(sig_cnt))
    print('average sig cnt : ',statistics.mean(sig_cnt))
    
    
    print('\nmax sig len : ',max(len_list))
    print('min sig len : ',min(len_list))
    print('average sig len : ',statistics.mean(len_list))
    
def sub_sig_cnt(input_dir):
    cnt = 0
    section_list = []
    
    with open(input_dir, "r", encoding="utf-8") as file:
        content = file.read()

    content = content.split('--------------------------------------------------')
    
    for line in content:        
        
        lines = line.strip().split('\n')
        print(lines, len(lines)-1)
        cnt+=len(lines)-1
            
    print(cnt)
    
def main(input_dir):
    #sub_sig_cnt(input_dir)
    #sig_ratio(input_dir)
    sig_section_ratio(input_dir)
    #ldb_sig_len(input_dir)

            

if __name__ == '__main__':
   
    input_dir = '../find_sig.txt'    
    main(input_dir)        
        
        
        
        