# coding:utf-8
# get Betweeness
import networkx as nx
import pdb


def betweeness(g):
	betweenness = nx.betweenness_centrality(g)
	return betweenness


def eigenvector(g):
	centrality = nx.eigenvector_centrality(g)
	return centrality


def closeness_centrality(g):
	closeness = nx.closeness_centrality(g)
	return closeness


def retrieveGP(g):
	bf = betweeness(g)
	x = sorted(bf.values())
	value = sum(x)/len(x)
	return round(value, 5)
