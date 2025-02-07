#coding:utf-8
import itertools
import sys
sys.path.insert(0, '/usr/local/lib/python2.7/dist-packages/')
import networkx as nx
#import numpy as np
from subprocess import Popen, PIPE
import pdb
import os
import re, mmap
import jsonlines
#from graph_edit_new import *

def write_data_to_filename(filename, data):
    # data = json.dumps(data)
    with jsonlines.open(filename, mode='a') as writer:
        writer.write(data)

class raw_graph:
	def __init__(self, funcname, g, func_f=None):
		self.funcname = funcname
		self.old_g = g
		self.g = nx.DiGraph()
		self.discovre_features = func_f
		self.attributing()

	def __len__(self):
		return len(self.g)

	def attributing(self):
		if False:
			self.obtainOffsprings(self.old_g)

		for node in self.old_g:
			fvector = self.retrieveVec(node, self.old_g)  
			self.g.add_node(node)
			self.g.nodes[node]['v'] = fvector

		for edge in self.old_g.edges():
			node1 = edge[0]
			node2 = edge[1]
			self.g.add_edge(node1, node2)

	def obtainOffsprings(self, g):
		nodes = g.nodess()
		for node in nodes:
			offsprings = {}
			self.getOffsprings(g, node, offsprings)
			g.nodes[node]['offs'] = len(offsprings)
		return g

	def getOffsprings(self, g, node, offsprings):
		node_offs = 0
		sucs = g.successors(node)
		for suc in sucs:
			if suc not in offsprings:
				offsprings[suc] = 1
				self.getOffsprings(g, suc, offsprings)

	def retrieveVec(self, id_, g):
		feature_vec = []
		numc = g.nodes[id_]['consts']
		feature_vec.append(numc)

		nums = g.nodes[id_]['strings']
		feature_vec.append(nums)

		numAs = g.nodes[id_]['numAs']
		feature_vec.append(numAs)

		# of calls3
		calls = g.nodes[id_]['numCalls']
		feature_vec.append(calls)

		# of insts4
		insts = g.nodes[id_]['numIns']
		feature_vec.append(insts)

		# of LIs5
		insts = g.nodes[id_]['numLIs']
		feature_vec.append(insts)

		# of TIs6
		insts = g.nodes[id_]['numTIs']
		feature_vec.append(insts)

		# of CmpIs7
		insts = g.nodes[id_]['numCmpIs']
		feature_vec.append(insts)

		# of MovIs8
		insts = g.nodes[id_]['numMovIs']
		feature_vec.append(insts)

		# of TermIs9
		insts = g.nodes[id_]['numTermIs']
		feature_vec.append(insts)

		# of DefIs10
		insts = g.nodes[id_]['numDefIs']
		feature_vec.append(insts)

		return feature_vec


class raw_graphs:
	def __init__(self, binary_name):
		self.binary_name = binary_name
		self.raw_graph_list = []

	def append(self, raw_g):
		self.raw_graph_list.append(raw_g)

	def __len__(self):
		return len(self.raw_graph_list)
