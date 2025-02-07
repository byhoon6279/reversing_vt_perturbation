import os

def malguise(args):
    sample, root, save_dir = args
    input_filepath = os.path.join(root, sample)
    os.system('python ./modifier/MalGuise/src/utils/pe_patcher/get_call_addr.py -f '+input_filepath)
    os.system('python ./modifier/MalGuise/src/utils/pe_patcher/patcher_custom.py -f '+input_filepath)
    
    os.system('rm -rf '+input_filepath+'.i64')
    os.system('rm -rf '+input_filepath+'.txt')
    os.system('mv '+input_filepath.replace('.exe','_malguise.exe')+' ./m_sample_2/'+input_filepath.replace('.exe','_malguise.exe'))