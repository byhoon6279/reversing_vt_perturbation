# coding:utf-8
from func import *
from raw_graphs import *
import idc
import idaapi
import idautils
import os
import json
import networkx as nx
import jsonlines
import time
import omegaconf
from pathlib import Path
import ida_auto
import ida_nalt
import ida_pro

p = Path(os.path.abspath(__file__))
base_path = str(p.parents[3])
cfg_path = os.path.join(base_path, 'configs/model_and_data.yaml')
config = omegaconf.OmegaConf.load(cfg_path)


def read_data_from_jsonl(filename):
    with open(filename, "r+") as f:
        for item in jsonlines.Reader(f):
            print(item)


def write_data_to_filename(filename, data):
    # data = json.dumps(data)
    with jsonlines.open(filename, mode='w') as writer:
        writer.write(data)


def get_acfg():
    start_time = int(time.time())
    cfgs, flag = get_func_cfgs_c(start_time)
    if flag is True:
        with open(os.path.join(base_path, 'src/utils/acfg_extractor/quit.log'), 'a+') as f:
            f.write(ida_nalt.get_root_filename() + ' time out; start_time: ' + str(start_time) + '; end_time: ' + str(int(time.time())) + '\n')
        f.close()
        ida_pro.qexit(0)
    output = {}
    for func in cfgs.raw_graph_list:
        name = func.funcname
        features = func.discovre_features
        block_start_node = []
        block_end_node = []
        for item in features[0]:
            block_start_node.append(item[0])
            block_end_node.append(item[1])

        a_fea = []
        for i in range(len(func.g.nodes)):
            each_node_features = func.g.nodes[i]['v']
            node = [len(each_node_features[0]), len(each_node_features[1]), each_node_features[2], each_node_features[3],
                    each_node_features[4], each_node_features[5], each_node_features[6], each_node_features[7],
                    each_node_features[8], each_node_features[9], each_node_features[10]]
            a_fea.append(node)
        fea = {'block_edges': [block_start_node, block_end_node], 'block_number': len(a_fea), 'block_features': a_fea}
        output.setdefault(name, fea)
    return output


def parse_gdl(filename, function_acfg):
    f = open(filename, 'r')
    line = f.readline()
    edge_list = []
    external_function = []
    internal_function = []
    function_acfg_list = []
    order_function = []
    flag = True
    while line:
        data = line.strip('\n')
        if data.startswith('node:'):
            node_item_list = data.split(' ')
            function_name = node_item_list[5].replace('"', '')
            if function_name in function_acfg and node_item_list[7] != '80' and '.' != function_name[0]:
                internal_function.append(function_name)
                function_acfg_list.append(function_acfg[function_name])
            else:
                external_function.append(function_name)
            order_function.append(function_name)
        elif data.startswith('edge:'):
            node_item_list = data.split(' ')
            source = order_function[int(node_item_list[3].replace('"', ''))]
            target = order_function[int(node_item_list[5].replace('"', ''))]
            # if source in internal_function and target in internal_function:
            edge_list.append({'source': source, 'target': target})
        line = f.readline()
    f.close()
    total_function = internal_function + external_function
    return edge_list, total_function, function_acfg_list


def get_all_sub_graph(edge_list):
    big_cfg = nx.DiGraph()
    for item in edge_list:
        big_cfg.add_node(item['source'])
        big_cfg.add_node(item['target'])
        big_cfg.add_edge(item['source'], item['target'])
    undirected_big_cfg = big_cfg.to_undirected()
    connected_graph = list(nx.connected_components(undirected_big_cfg))
    total_graph = []
    for graph_item in connected_graph:
        sub_graph = big_cfg.subgraph(list(graph_item))
        total_graph.append(list(sub_graph.edges))
    return total_graph


if __name__ == '__main__':
    idaapi.auto_wait()
    #ida_auto.autoWait
    pe_filename = ida_nalt.get_root_filename()
    pe_filename = pe_filename.split(".")[0]
    base_dir = os.path.join(base_path, "src/utils/acfg_extractor")
    dst_path = os.path.join(base_dir, 'dst')
    gdl_path = os.path.join(base_path, "src/utils/acfg_extractor/gdl/")
    if os.path.exists(gdl_path) is False:
        os.makedirs(gdl_path)
    saved_path = os.path.join(base_path, config.Malgraph.Model.tmp_sample_root)
    call_graph_and_acfg_filename = os.path.join(saved_path, pe_filename + '.json')
    
    start_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    output = get_acfg()
    
    gdl_filename = os.path.join(gdl_path, pe_filename)
    res = idaapi.gen_simple_call_chart(gdl_filename, '', 'title', 0)
    if res is True:
        edge_list, total_function, function_acfg_list = parse_gdl(gdl_filename + '.gdl', output)
    else:
        with open(os.path.join(base_dir, 'error.log'), 'a+') as f:
            f.write(pe_filename + ' get call graph failed\n')
        f.close()
        ida_pro.qexit(0)

    function_start_node = []
    function_end_node = []
    for item in edge_list:
        function_start_node.append(total_function.index(item['source']))
        function_end_node.append(total_function.index(item['target']))

    data = {'hash': pe_filename, 'function_number': len(total_function),
            'function_edges': [function_start_node, function_end_node], 'function_names': total_function,
            'acfg_list': function_acfg_list}


    write_data_to_filename(call_graph_and_acfg_filename, data)

    end_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    with open(os.path.join(base_dir, 'time.log'), 'a+') as f:
        f.write(pe_filename + ' start: ' + start_time + '; end: ' + end_time + '\n')
    f.close()
    ida_pro.qexit(0)
