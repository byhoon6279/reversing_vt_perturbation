# -*- coding: utf-8 -*- 
import subprocess
import omegaconf
import argparse
import os
from pathlib import Path

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', default = '', type = str, dest = 'filename')
    args = parser.parse_args()
    data_path = args.filename
    p = Path(os.path.abspath(__file__))
    base_path = str(p.parents[3])
    cfg_path = os.path.join(base_path, 'configs/preprocess.yaml')
    config = omegaconf.OmegaConf.load(cfg_path)
    IDA_PATH = config.IDA_PATH
    SCRIPT_PATH = os.path.join(base_path, config.Acfg.SCRIPT_PATH)

    cmd = IDA_PATH + ' -A -S' + SCRIPT_PATH + ' ' + data_path
    print(cmd)
    p = subprocess.Popen(cmd, shell=True)
    p.wait()
