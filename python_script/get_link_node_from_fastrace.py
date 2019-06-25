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
def get_fastrace_packet_by_file():
	ffile=sys.argv[1]
	fastrace_dic={}
	fastrace_dic['file']=ffile
	fastrace_dic['ALL_TARGET']=0
	fastrace_dic['ALL_SEND_PACKET']=0
	fastrace_dic['ALL_NODE']=0	
	fastrace_dic['ALL_LINK']=0	
	fastrace_dic['MID_ROUTER_COUNT']=0	#中间路由器数目，
	fastrace_dic['TARGET_ARRIVE']=0
	fastrace_dic['HOPPING_SEND']=0
	fastrace_dic['BNP_REDUNDANCE_COUNT']=0
	fastrace_dic['BNP_REDUNDANCE_RATE']=0.0
	fastrace_dic['BNP_COUNT']=0
	fastrace_dic['NNS_COUNT']=0
	fastrace_dic['RUNTIME']=0
	fastrace_dic['MAX_HOP_AVG']=0
	fastrace_dic['BNP_AVG']=0
	fastrace_dic['all_hop']=0
	fastrace_dic['src']=0
	fastrace_dic['info']={}
	fastrace_dic['broken']=0
	fastrace_dic['link_set']=set()
	fastrace_dic['node_set']=set()
	fastrace_dic['router_set']=set()
	#每个目标统计信息：bnp=1,hop={},
	fr=open(ffile,'r')
	lines=fr.readlines()
	if len(lines) <2 or ("RUNTIME" not in lines[-1]):	#文件未正常结束
		fastrace_dic['broken']=1
		print "!!!!!!!!!!!!!!!!!!!",ffile+": no complete !"
		return fastrace_dic
	pline=""
	line=""
	fr.seek(0,0)
	line=fr.readline()
	dst=""
	if not line:
		print "!!!!!!!!!!!!!!!!!!!",ffile+": no complete !"
		fastrace_dic['broken']=1
		return fastrace_dic
	while True:
		pline=line
		line=fr.readline()
		if not line:
			break
		if "ALL_TARGET" in line:
			fastrace_dic['ALL_TARGET']=int(line.split()[1])
		if "ALL_SEND_PACKET" in line:
			fastrace_dic['ALL_SEND_PACKET']=int(line.split()[1])
		if "BNP_REDUNDANCE_COUNT" in line:
			fastrace_dic['BNP_REDUNDANCE_COUNT']=int(line.split()[1])
		if "ALL_NODE" in line:
			fastrace_dic['ALL_NODE']=int(line.split()[1])
		if "ALL_LINK" in line:
			fastrace_dic['ALL_LINK']=int(line.split()[1])
		if "TARGET_ARRIVE" in line:
			fastrace_dic['TARGET_ARRIVE']=int(line.split()[1])			
		if "BNP_COUNT" in line:
			fastrace_dic['BNP_COUNT']=int(line.split()[1])
		if "NNS_COUNT" in line:
			fastrace_dic['NNS_COUNT']=int(line.split()[1])
		if "RUNTIME" in line:
			fastrace_dic['RUNTIME']=int(line.split()[1].split('.')[0])
		try:
			if "Target" in pline:		#获取源与第一跳链接
				dst= pline.split()[1]#.decode('unicode_escape')
				src=pline.split()[7]
				#记录每一跳
				# print "fastrace",type(dst),dst
				dst=str(dst)
				fastrace_dic['info'][dst]={}
				fastrace_dic['info'][dst]['bnp']=0
				fastrace_dic['info'][dst]['hop']={}
				fastrace_dic['info'][dst]['maxhop']=0
				# print pline
				fastrace_dic['info'][dst]['bnp']=int(pline.split()[9])
				#获取源与第一跳链接
				if line[0] == '~' and line.split()[2]!="0":
					s=src
					d=line.split()[2]
					ip_s=socket.ntohl(struct.unpack("I",socket.inet_aton(s))[0])
					ip_d=socket.ntohl(struct.unpack("I",socket.inet_aton(d))[0])
					if ip_s !=0 and ip_d != 0:
						if ip_s>ip_d:
							str_ip=d+" "+s
						else:
							str_ip=s+" "+d
						fastrace_dic['link_set'].add(str_ip)
						# ftrace_all_link.add(str_ip)
				else:
					pass
					# print ffile+" error no hop after Target"+line
					# return fastrace_dic

			if line[0] == '~':			#获取节点和中间路由器
				node=line.split()[2]
				if node !="0":
					# ftrace_all_node.add(node)
					fastrace_dic['node_set'].add(node)
					if node!=dst:			#统计中间路由器
						# fastrace_dic['MID_ROUTER_COUNT']+=1
						fastrace_dic['router_set'].add(node)
					#先读目标，后读跳,获取每一跳
					fastrace_dic['all_hop']+=1

					index_hop=int(line.split()[1])	
					fastrace_dic['info'][dst]['hop'][index_hop]=node
					fastrace_dic['info'][dst]['maxhop']=index_hop
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
				fastrace_dic['link_set'].add(str_ip)
				# ftrace_all_link.add(str_ip)
		except Exception as e:
			print ffile,"error in get_fastrace_packet_by_file",e
			print pline
			print line
			fastrace_dic['broken']=1
			return fastrace_dic
	if len(fastrace_dic['link_set'])==0 or len(fastrace_dic['node_set'])==0 or fastrace_dic['ALL_TARGET']==0:
		fastrace_dic['broken']=1
		print "!!!!!!!!!!!!!!!!!!!",ffile,"no any data in file!!!!!!!!!!!!!!!"
		return fastrace_dic

	fastrace_dic['src']=src
	fastrace_dic['MID_ROUTER_COUNT']=len(fastrace_dic['router_set'])
	print ">fastrace"
	print "src",fastrace_dic['src']
	print "broken",fastrace_dic['broken']
	print "BNP_COUNT",fastrace_dic['BNP_COUNT']
	print "NNS_COUNT",fastrace_dic['NNS_COUNT']
	print "ALL_TARGET",fastrace_dic['ALL_TARGET']
	print "ALL_SEND_PACKET",fastrace_dic['ALL_SEND_PACKET']
	print "ALL_NODE",fastrace_dic['ALL_NODE']
	print "ALL_LINK",fastrace_dic['ALL_LINK']
	print "MID_ROUTER_COUNT",fastrace_dic['MID_ROUTER_COUNT']
	print "link_set",len(fastrace_dic['link_set'])
	print "node_set",len(fastrace_dic['node_set'])
	print "router_set",len(fastrace_dic['router_set'])
	print "TARGET_ARRIVE",fastrace_dic['TARGET_ARRIVE']
	print "BNP_REDUNDANCE_COUNT",fastrace_dic['BNP_REDUNDANCE_COUNT']
	print "BNP_COUNT",fastrace_dic['BNP_COUNT']
	print "NNS_COUNT",fastrace_dic['NNS_COUNT']
	print "all_hop",fastrace_dic['all_hop']
	print "RUNTIME",fastrace_dic['RUNTIME']
	if fastrace_dic['ALL_SEND_PACKET']>0:
		fastrace_dic['BNP_REDUNDANCE_RATE']=fastrace_dic['BNP_REDUNDANCE_COUNT']*1.0/(fastrace_dic['ALL_SEND_PACKET']+fastrace_dic['BNP_REDUNDANCE_COUNT'])
		print "rebundary rate:",fastrace_dic['BNP_REDUNDANCE_RATE']
	for dst in fastrace_dic['info']:
		fastrace_dic['MAX_HOP_AVG']+=fastrace_dic['info'][dst]['maxhop']
		fastrace_dic['BNP_AVG']+=fastrace_dic['info'][dst]['bnp']
	fastrace_dic['MAX_HOP_AVG']	=fastrace_dic['MAX_HOP_AVG']*1.0/fastrace_dic['ALL_TARGET']
	fastrace_dic['BNP_AVG']		=fastrace_dic['BNP_AVG']*1.0/fastrace_dic['ALL_TARGET']
	print "MAX_HOP_AVG",fastrace_dic['MAX_HOP_AVG']
	print "BNP_AVG",fastrace_dic['BNP_AVG'],(fastrace_dic['BNP_AVG']-1)*1.0/fastrace_dic['MAX_HOP_AVG']
	if sys.argv[2] == "1":
		fw=open(sys.argv[1]+".link",'w')
		for item in fastrace_dic['link_set']:
			fw.write(item+"\n")
		fw.close()

		fw=open(sys.argv[1]+".node",'w')
		for item in fastrace_dic['node_set']:
			fw.write(item+"\n")
		fw.close()
	if sys.argv[2] == "2":
		fw=open(sys.argv[1]+".csv",'w')
		for item in fastrace_dic['link_set']:
			fw.write(item.split()[0]+','+item.split()[1]+"\n")
		fw.close()

		fw=open(sys.argv[1]+".node",'w')
		for item in fastrace_dic['node_set']:
			fw.write(item+"\n")
		fw.close()
	return fastrace_dic
def draw(edge_set,node_set):
	G = nx.Graph()
	for node in node_set:
		G.add_node(node)
	for edge in edge_set:
		G.add_edge(edge.split()[0],edge.split()[1])
	nx.draw(G)
	plt.draw()
if __name__ == '__main__':
	# get_node_link()
	get_fastrace_packet_by_file()


def run_all_vps_data():
	for dirpath, dirnames, filenames in os.walk(sys.argv[1]):
		# for filepath in filenames:
		#     print os.path.join(dirpath, filepath)
		for dirname in dirnames:
			# print dirname
			# print dirpath
			ffile=dirpath+dirname+"/test-fastrace"+sys.argv[2]+".fastrace"
			f_ip_file=dirpath+dirname+"/test-fastrace"+sys.argv[2]+".ip_list"
			if os.path.exists(ffile):
				print "--------------------"
				print ffile
				fastrace_dic=get_fastrace_packet(ffile)
				if fastrace_dic['src']==0:
					continue
				fw=open("csv-fastrace4/"+fastrace_dic['src']+dirname+".csv",'w')
				for item in fastrace_dic['link_set']:
					fw.write(item.split()[0]+','+item.split()[1]+"\n")
				fw.close()