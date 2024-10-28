import shutil
import os

input_dir = '../malware.txt'

with open(input_dir, "r", encoding="utf-8") as file:
    content = file.read()

content = content.split('\n')
for line in content:
    if not line:
        break
        
    #benign    
#     if '.exe' in line and 'OK' in line:
#         line = line.split(':')[0]
#         source = line
#         file = line.split('/')[-1]
#         shutil.copy(source, './sample/Dike_benign/')
        
    #malware
    if 'OK' not in line and '.exe' in line:
        #/home/younghoon.ban/DikeDataset/files/benign/2a922ebe7edb08480baa1721ce1b5185fb5af7f64ec0f128d6a7a37711784815.exe: Win.Ransomware.Midie-9980258-0 FOUND
        fam = line.split(':')[-1].split('-')[0]
        fam = fam.replace(' FOUND','').strip().lower()
        
        source = line.split(':')[0]
        
        dest_dir = os.path.join('../sample/Dike_malware/', fam)
        print(dest_dir)
        os.makedirs(dest_dir, exist_ok=True)
        
        dest_file_path = os.path.join(dest_dir, os.path.basename(source))
        #print(dest_file_path)
        shutil.copy(source, dest_file_path)
        
        