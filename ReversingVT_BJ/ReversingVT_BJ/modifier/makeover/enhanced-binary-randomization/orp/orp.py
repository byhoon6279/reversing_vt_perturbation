#!/usr/bin/env python

# Copyright (c) 2012, Vasilis Pappas <vpappas@cs.columbia.edu>
# This file is part of Orp http://nsl.cs.columbia.edu/projects/orp

# Additionally modified by Mahmood Sharif <mahmoods@alumni.cmu.edu>
# Alternate contact is Keane Lucas <keanelucas@cmu.edu>

import optparse
import itertools
import random
import subprocess
import os
import sys
import pefile
import copy

import func
import eval
import inp

import swap
import reorder
import equiv
import preserv
import shlex

VER="0.3"

# check for the prerequisites
try:
  import pydasm
except ImportError as e:
  print("pydasm is not installed")
  sys.exit(1)

#TODO: check that pydasm is patched!

try:
  import pygraph
except ImportError as e:
  print("pygraph is not installed")
  sys.exit(1)

import os

def patch(pe_file, diffs):
  """
  Patch the pe_file according to the provided diffs (apply the diffs).
  """
  base = pe_file.OPTIONAL_HEADER.ImageBase
  
  # 파일이 read-only 상태인지 확인하고 쓰기 가능하도록 변경
  if not os.access(pe_file.filename, os.W_OK):
    print(f"File {pe_file.filename} is read-only. Changing permissions...")
    os.chmod(pe_file.filename, 0o666)  # 쓰기 가능하도록 변경
  
  for ea, orig, new in diffs:
    
    # (1) 주소가 유효한지 확인
    if not (0 <= ea - base < len(pe_file.__data__)):
      print(f"Invalid write attempt at {hex(ea)} (base: {hex(base)})")
      continue  # 건너뛰기

    # (2) 현재 바이트와 예상 바이트가 다른 경우 확인
    curr = pe_file.get_data(ea - base, 1)
    if curr != orig:
      print(f"Warning: mismatch at {hex(ea)} - expected {orig}, found {curr}")
      force_patch = True  # 강제 패치 여부
      if not force_patch:
        continue  # 원래 값이 다르면 건너뛰기

    # (3) 바이트 수정 적용
    try:
      if ea < base:
        pe_file.set_bytes_at_offset(ea, new)
      else:
        pe_file.set_bytes_at_rva(ea - base, new)
    except Exception as e:
      print(f"Failed to set bytes at {hex(ea)}: {e}")


def randomize(input_file, n_randomize=10):

  pe_file = pefile.PE(input_file)
  
  # get the changed byte sets
  functions = inp.get_functions(input_file)
  levels = func.classify_functions(functions)
  func.analyze_functions(functions, levels)

  # see what happens when randomizing again and again and again...
  for i_r in range(n_randomize):
    # copy pe_file and functions
    #pe_file = copy.deepcopy(pe_file)
#    functions = copy.deepcopy(functions)
    functions = copy.copy(functions)  # 얕은 복사 사용

  
    global_diffs = []
    changed_bytes = set()
    changed_insts = set()

    for f in [x for x in iter(functions.values()) if x.level != -1]:

      # skip the SEH prolog and epilog functions .. they cause trouble
      if "_SEH_" in f.name:  
        continue

      # equiv
      diffs, c_b, c_i = equiv.do_equiv_instrs(f)
      if diffs:
        changed_bytes.update(c_b)
        changed_insts.update(c_i)
        global_diffs.extend(diffs)
        patch(pe_file, diffs)
    
      # swap
      swap.liveness_analysis(f.code)
      live_regs = swap.get_reg_live_subsets(f.instrs, f.code, f.igraph)
      swaps = swap.get_reg_swaps(live_regs)
      # count = 0
      # for comb in swap.gen_swap_combinations(swaps):
      #   # if len(comb)>1:
      #   #   print(comb)
      #   #   exit(0)
      #   count += 1
      # # print('Count=%d'%(count,))
      diffs, c_b, c_i = swap.do_multiple_swaps(f, swaps)
      if diffs:
        changed_bytes.update(c_b)
        changed_insts.update(c_i)
        global_diffs.extend(diffs)
        patch(pe_file, diffs)

      # preserv
      preservs, avail_regs = preserv.get_reg_preservations(f)
      # print('f.reg_pairs: %s'%(f.reg_pairs,))
      # print('preservs: %s'%(preservs,))
      # print('avail_regs: %s'%(avail_regs,))
      diffs, c_b, c_i = preserv.do_reg_preservs(f, preservs, avail_regs)
      if diffs:
        changed_bytes.update(c_b)
        changed_insts.update(c_i)
        global_diffs.extend(diffs)
        patch(pe_file, diffs)
        
      # reorder
      diffs, c_b = reorder.do_random_reordering(f, pe_file)
      if diffs:
        changed_bytes.update(c_b)
        global_diffs.extend(diffs)
        patch(pe_file, diffs)
        
    # update
    print("done with randomization iter #%d: changed %d bytes (and %d instructions)"%(i_r,len(changed_bytes),len(changed_insts)))

    # reanalyze functions (if not the last iteration)
    if i_r<n_randomize-1:
      for f in functions.values():
        f.arg_regs = set()
        f.ret_regs = set()
        f.pre_regs = set()
        f.ret_regs = set()
        f.reg_pairs = []
      func.analyze_functions(functions, levels)

  # write output
  output_file = input_file.replace(".exe", "_patched-w-compositions.exe")
  pe_file.write(output_file)
  pe_file.close()


def call_ida(input_file):
  script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "inp_ida.py")
  #script = "/home/younghoon.ban/enhanced-binary-diversification/enhanced-binary-randomization/orp/inp_ida.py"

  if not os.path.exists(script):
    print("error: could not find inp_ida.py (%s)" % script)
    sys.exit(1)
  command = '/opt/idapro-8.3/idat -A -S"\\"' + script + '\\"" ' + input_file
  print("executing:", command)
  #exit_code = subprocess.call(command)
  exit_code = subprocess.call(shlex.split(command))
  print("exit code:", exit_code)

# ✅ .idb 파일 삭제 함수
def delete_idb_files(directory):
    """ Delete all .idb files in the specified directory """
    idb_files = [f for f in os.listdir(directory) if f.endswith(".idb")]
    for idb_file in idb_files:
        idb_path = os.path.join(directory, idb_file)
        try:
            os.remove(idb_path)
            print(f"🗑️ Deleted: {idb_path}")
        except Exception as e:
            print(f"⚠️ Error deleting {idb_path}: {e}")

if __name__=="__main__":
    parser = optparse.OptionParser("usage: %prog [options] input_file_or_directory")

    parser.add_option("-p", "--profile", dest="profile",
                      action="store_true", default=False,
                      help="profile the execution")

    parser.add_option("-c", "--eval-coverage", dest="coverage",
                      action="store_true", default=False,
                      help="evaluate the randomization coverage")

    parser.add_option("-e", "--eval-payload", dest="payload",
                      action="store_true", default=False,
                      help="check if the payload of the exploit can be broken")

    parser.add_option("-d", "--dump-cfg", dest="dump_cfg",
                      action="store_true", default=False,
                      help="dump the CFG of the input file (using IDA)")

    parser.add_option("-r", "--randomize", dest="randomize",
                      action="store_true", default=True,
                      help="produce a randomized instance of input (default)")

    parser.add_option("-D", "--dir", dest="directory",
                      action="store", type="string",
                      help="Specify a directory to process all .exe files")

    (options, args) = parser.parse_args()

    print("Orp v%s" % VER)

    # ✅ **디렉토리 모드: -D 옵션이 있을 경우**
    if options.directory:
        if not os.path.isdir(options.directory):
            parser.error("Invalid directory: '%s'" % options.directory)

        exe_files = [f for f in os.listdir(options.directory) if f.endswith(".exe")]
        if not exe_files:
            parser.error("No .exe files found in directory: '%s'" % options.directory)

        for exe in exe_files:
            input_file = os.path.join(options.directory, exe)
            print(f"Processing {input_file} ...")

            if options.dump_cfg:
                call_ida(input_file)
            elif options.randomize:
                randomize(input_file)
            else:
                print(f"Skipping {input_file} (no valid action specified)")

        print("✅ All .exe files processed.")
        
        # ✅ 실행 완료 후 .idb 파일 삭제 (디렉토리 모드)
        delete_idb_files(options.directory)
        print("✅ All .idb files deleted.")

        sys.exit(0)

    # ✅ **단일 파일 모드 (기존 방식)**
    if len(args) == 0:
        parser.error("No input file")
    elif len(args) > 1:
        parser.error("More than one input file")

    # ✅ **입력된 파일이 존재하는지 확인**
    if not os.path.exists(args[0]):
        parser.error("Cannot access input file '%s'" % args[0])

    # ✅ **각 옵션에 따라 동작**
    if options.profile and options.dump_cfg:
        parser.error("Cannot profile the CFG extraction from IDA")

    if options.profile:
        import cProfile
        _run = cProfile.run
    else:
        _run = __builtins__.eval

    if options.coverage:
        _run('eval.eval_coverage(args[0])')
    elif options.payload:
        _run('eval.eval_exploit(args[0])')
    elif options.dump_cfg:
        call_ida(args[0])
    elif options.randomize:
        _run('randomize(args[0])')
    else:
        parser.error("How did you do that?")

    # ✅ **단일 파일 모드에서도 실행 완료 후 .idb 파일 삭제**
    input_file_dir = os.path.dirname(args[0])  # 실행한 파일이 있는 디렉토리
    delete_idb_files(input_file_dir)
    print("✅ All .idb files deleted from", input_file_dir)


