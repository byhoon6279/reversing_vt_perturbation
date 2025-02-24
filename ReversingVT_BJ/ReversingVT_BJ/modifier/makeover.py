import os

def makeover(args):
    sample, root, save_dir = args
    input_filepath = os.path.join(root, sample)
    
    os.system(f'python ./modifier/makeover/enhanced-binary-randomization/orp/orp.py -d "{input_filepath}"')
    os.system(f'python ./modifier/makeover/binary_transform.py --pe "{input_filepath}"')
    
    cfg_file = sample.replace('.exe','.exe.dmp.bz2')
    cfg_filepath = os.path.join(root, cfg_file)
    os.system(f'rm -rf "{cfg_filepath}"')
    
    output_file = sample.replace('.exe','_patched-w-compositions.exe')
    output_filepath = os.path.join(save_dir, output_file)
    os.system(f'mv "{input_filepath.replace(".exe", "_patched-w-compositions.exe")}" "{output_filepath.replace("_patched-w-compositions.exe", "_makeover.exe")}"')
