import sys
import os

# ✅ IDA Python 환경 강제 설정
IDA_PYTHON_HOME = "/opt/idapro-8.3/python/3"
IDA_PYTHON_LIB = "/opt/idapro-8.3/python/lib/python3.8/site-packages"
IDA_64_PATH = "/opt/idapro-8.3/python/3/ida_64"

# ✅ Anaconda 가상환경 설정
ANACONDA_ENV_PATH = "/home/younghoon.ban/anaconda3/envs/usenix"
ANACONDA_SITE_PACKAGES = os.path.join(ANACONDA_ENV_PATH, "lib/python3.8/site-packages")

# ✅ Anaconda 환경 패키지를 sys.path에 추가
if ANACONDA_SITE_PACKAGES not in sys.path:
    sys.path.insert(0, ANACONDA_SITE_PACKAGES)

# ✅ 환경 변수 설정
os.environ["PYTHONHOME"] = ANACONDA_ENV_PATH  # Anaconda 환경을 기본 Python으로 설정
os.environ["PYTHONPATH"] = f"{ANACONDA_SITE_PACKAGES}:{IDA_PYTHON_HOME}:{IDA_64_PATH}:{IDA_PYTHON_LIB}"
os.environ["LD_LIBRARY_PATH"] = f"{ANACONDA_ENV_PATH}/lib:/opt/idapro-8.3:/opt/idapro-8.3/python/3:/opt/idapro-8.3/python/3/ida_64"

# ✅ Python 실행 경로 확인
print("🛠️ 현재 실행 중인 Python:", sys.executable)

# ✅ networkx 모듈 불러오기 테스트
try:
    import networkx as nx
    print("✅ networkx 모듈 로드 성공!")
except ModuleNotFoundError:
    print("❌ networkx 모듈을 찾을 수 없습니다! 환경 변수를 확인하세요.")
    sys.exit(1)

# ✅ IDAPython 모듈 불러오기 테스트
try:
    import idaapi
    import idc
    import idautils
    print("✅ IDAPython (idaapi) 모듈 로드 성공!")
except ModuleNotFoundError:
    print("❌ IDAPython (idaapi) 모듈을 찾을 수 없습니다! 환경 변수를 확인하세요.")
    sys.exit(1)


from idaapi import *
from idautils import *
from idc import *
import idc
import networkx as nx
import cfg_constructor as cfg
#import cPickle as pickle
import pickle
import pdb
import time
from raw_graphs import *
from discovRe import *
import jsonlines
import ida_segment

def write_data_to_filename(filename, data):
    # data = json.dumps(data)
    with jsonlines.open(filename, mode='a') as writer:
        writer.write(data)
		
def get_seg_list():
	result = []
	total_seg_number = get_segm_qty()
	for n in range(total_seg_number):
		seg = getnseg(n)
		#ea = seg.startEA
		ea = seg.start_ea
		seg_type = segtype(ea)
		if seg_type in [1, 3, 7, 8, 9]:
			continue
		result.append(seg)
	return result


def get_func_cfgs_c(start_time):
	#binary_name = GetInputFile()
	binary_name = idc.get_input_file_path()
	raw_cfgs = raw_graphs(binary_name)
	externs_eas, ea_externs = processpltSegs()
	seg_list = get_seg_list()
	flag = False
	i = 0
	for segm in seg_list:
		#for funcea in Functions(segm.startEA, segm.endEA):
		for funcea in Functions(segm.start_ea, segm.end_ea):
			
			funcname = get_unified_funcname(funcea)
			
			func = get_func(funcea)

			icfg = cfg.getCfg(func, externs_eas, ea_externs)
			
			i = i + 1
			end_time = int(time.time())
			func_f = get_discoverRe_feature(funcea, func, icfg)
			#blocks = [(hex(v.startEA), hex(v.endEA)) for v in FlowChart(func)]
			blocks = [(hex(v.start_ea), hex(v.end_ea)) for v in FlowChart(func)]
			#Insts = getIntrs(func)
			#Insts = getIntrs(func)
			if func_f is None:
				flag = True
				break
			end_time = int(time.time())
			if end_time - start_time >= 300:
				flag = True
				break
			raw_g = raw_graph(funcname, icfg, func_f)
			raw_cfgs.append(raw_g)
			
		if flag is True:
			break
	
	return raw_cfgs, flag


def get_unified_funcname(ea):
	#funcname = GetFunctionName(ea)
	funcname = idc.get_func_name(ea)
	return funcname

def processpltSegs():
	funcdata = {}
	datafunc = {}
	for n in range(get_segm_qty()):
		seg = getnseg(n)
		#ea = seg.startEA
		ea = seg.start_ea
		#segname = SegName(ea) #ida_segment.get_segm_name(ida_segment.getseg(ea))
		segname = ida_segment.get_segm_name(ida_segment.getseg(ea))
		if segname in ['.plt', 'extern', '.MIPS.stubs']:
			#start = seg.startEA
			start = seg.start_ea
			#end = seg.endEA
			end = seg.end_ea
			cur = start
			while cur < end:
				name = get_unified_funcname(cur)
				funcdata[name] = hex(cur)
				datafunc[cur] = name
				cur = NextHead(cur)
	return funcdata, datafunc
