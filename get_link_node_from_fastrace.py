#!/usr/bin/env python
# -*- coding:utf-8 -*-
import os
import os.path
import sys
import subprocess
import time
import gzip
import datetime
import re
import struct
import socket
import json
# import networkx as nx
# import matplotlib.pyplot as plt
def get_node_link():
	fr=open(sys.argv[1],'r')
	pline=""
	line=""
	reply_dst_set=set()
	mid_is_dst_set=set()
	mid_router_set=set()
	mid_count=0
	link_set=set()
	node_set=set()
	dst_set=set()
	line=fr.readline()
	dst_link_count=0
	if not line:
		print("file in empty")
		return
	while True:
		pline=line
		line=fr.readline()
		if not line:
			break
		if "Target" in pline:
			dst= pline.split()[1]
			dst_set.add(dst)
			src=pline.split()[7]
			if line[0] == '~':
				link_set.add(src+" "+line.split()[2])
		if pline[0] == '~':
			node_set.add(pline.split()[2])
			if pline.split()[2]!=dst:
				mid_router_set.add(pline.split()[2])
		if line[0] == '~':
			node_set.add(line.split()[2])
			if line.split()[2]!=dst:
				mid_router_set.add(line.split()[2])
		if "Got there" in line:
			reply_dst_set.add(line.split()[1])
		if pline[0] == '~' and line[0] == '~':
			s=pline.split()[2]
			d=line.split()[2]
			ip_s=socket.ntohl(struct.unpack("I",socket.inet_aton(s))[0])
			ip_d=socket.ntohl(struct.unpack("I",socket.inet_aton(d))[0])
			if ip_s ==0 or ip_d == 0:
				continue
			if ip_s>ip_d:
				str_ip=d+" "+s
			else:
				str_ip=s+" "+d
			link_set.add(str_ip)
			if d==dst:
				dst_link_count+=1
	#delete dst from all node
	# for dst in dst_set:
	# 	if dst in node_set:
	# 		node_set.remove(dst)

	if sys.argv[2] == "1":
		fw=open(sys.argv[1]+".link",'w')
		for item in link_set:
			fw.write(item+"\n")
		fw.close()

		fw=open(sys.argv[1]+".node",'w')
		for item in node_set:
			fw.write(item+"\n")
		fw.close()
	# mid_count=len(node_set)-reply_count
	print "Target",len(dst_set)
	print "all link",len(link_set),"all node",len(node_set)
	print "dst link",dst_link_count
	print "reply dst count ",len(reply_dst_set)
	print "mid router count",len(mid_router_set)
	# print "the dst also is mid route:",len(reply_dst_set)+len(mid_router_set)-len(node_set)
	print "rely dst/all dst",len(reply_dst_set)*1.0/len(dst_set)

def draw(edge_set,node_set):
	G = nx.Graph()
	for node in node_set:
		G.add_node(node)
	for edge in edge_set:
		G.add_edge(edge.split()[0],edge.split()[1])
	nx.draw(G)
	plt.draw()
if __name__ == '__main__':
	get_node_link()