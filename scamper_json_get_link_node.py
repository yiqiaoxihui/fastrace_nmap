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
from IPy import IP
def get_link_node_from_dir():
	hops={}
	# list_dir = os.listdir(file_dir)
	link_set=set()
	node_set=set()
	all_packet=0
	all_time=0
	dst_set=set()
	all_ip=0
	# for file in list_dir:
	if True:
		fr=open(sys.argv[1],'r')
		# print file
		while True:
			line = fr.readline().strip()
			if not line:
				break
			else:
				all_ip+=1
				jo=json.loads(line)
				if jo.has_key('start_time'):
					start_time=int(jo['start_time'])
				if jo.has_key('stop_time'):
					stop_time=int(jo['stop_time'])
					all_time+=(stop_time-start_time)
				if jo.has_key('dst')==False:
					continue
				dst_set.add(jo['dst'])
				if jo.has_key('probe_count'):
					all_packet+=int(jo['probe_count'])
				dst=jo['dst']
				if jo.has_key('hops'):
					hops=jo['hops']
					len_hops=len(hops)
					if len_hops<=0:
						continue
					if int(hops[0]['probe_ttl'])==1:
						link_set.add(jo['src']+" "+hops[0]['addr'])	
					for i in range(0,len_hops-1):
						if (int)(hops[i]['probe_ttl']) +1  == int(hops[i+1]['probe_ttl']):
							# print (hops[i]['probe_ttl']),(hops[i+1]['probe_ttl'])
							s=hops[i]['addr']
							d=hops[i+1]['addr']
							if s == jo['dst']:
								print "how it come",jo['dst'],i
							ip_s=socket.ntohl(struct.unpack("I",socket.inet_aton(s))[0])
							ip_d=socket.ntohl(struct.unpack("I",socket.inet_aton(d))[0])
							if ip_s>ip_d:
								str_ip=d+" "+s
							else:
								str_ip=s+" "+d
							link_set.add(str_ip)
						node_set.add(hops[i]['addr'])
					node_set.add(hops[len_hops-1]['addr'])
		fr.close()
	# for dst in dst_set:
	# 	if dst in node_set:
	# 		node_set.remove(dst)
	print "all link",len(link_set),"all node",len(node_set),"all_packet",all_packet
	print "all time",all_time
	print "avg send packet",1.0*all_packet/all_time
	fw=open(sys.argv[1]+".link",'w')
	for item in link_set:
		fw.write(item+"\n")
	fw.close()
	
	fw=open(sys.argv[1]+".node",'w')
	for item in node_set:
		fw.write(item+"\n")
	fw.close()
		# print i,item
def get_scamper_packet_by_file():
	sfile=sys.argv[1]
	hops={}
	# list_dir = os.listdir(file_dir)
	scamper_dic={}
	scamper_dic['file']=sfile
	scamper_dic['ALL_TARGET']=0
	scamper_dic['ALL_SEND_PACKET']=0
	scamper_dic['ALL_NODE']=0	
	scamper_dic['ALL_LINK']=0	
	scamper_dic['MID_ROUTER_COUNT']=0	#中间路由器数目，
	scamper_dic['TARGET_ARRIVE']=0
	scamper_dic['RUNTIME']=0
	scamper_dic['all_hop']=0
	scamper_dic['src']=0
	scamper_dic['info']={}
	scamper_dic['link_set']=set()
	scamper_dic['node_set']=set()
	scamper_dic['router_set']=set()
	scamper_dic['broken']=0
	stop_time=0
	start_time=0
	# for file in list_dir:
	fr=open(sfile,'r')
	# print file
	
	while True:
		line = fr.readline().strip()
		if not line:
			break
		else:
			jo=json.loads(line)
			if jo.has_key('start_time'):
				start_time=int(jo['start_time'])
			if jo.has_key('stop_time'):
				stop_time=int(jo['stop_time'])
				scamper_dic['RUNTIME']=(stop_time-start_time)
			if jo.has_key('dst')==False:
				continue
			scamper_dic['ALL_TARGET']+=1
			if jo.has_key('probe_count'):
				scamper_dic['ALL_SEND_PACKET']+=int(jo['probe_count'])
			dst=jo['dst']
			src=jo['src']
			dst=str(dst)
			# print "scamper",type(dst),dst
			scamper_dic['info'][dst]={}
			scamper_dic['info'][dst]['hop']={}
			scamper_dic['info'][dst]['maxhop']=0
			if jo.has_key('hops'):
				hops=jo['hops']
				len_hops=len(hops)
				scamper_dic['all_hop']+=len_hops
				if len_hops<=0:
					continue
				if int(hops[0]['probe_ttl'])==1:
					s=src
					d=hops[0]['addr']
					ip_s=socket.ntohl(struct.unpack("I",socket.inet_aton(s))[0])
					ip_d=socket.ntohl(struct.unpack("I",socket.inet_aton(d))[0])
					if ip_s>ip_d:
						str_ip=d+" "+s
					else:
						str_ip=s+" "+d
					scamper_dic['link_set'].add(str_ip)
					# strace_all_link.add(str_ip)
				for i in range(0,len_hops-1):
					#节点
					# strace_all_node.add(hops[i]['addr'])
					scamper_dic['node_set'].add(hops[i]['addr'])
					#路由器
					scamper_dic['router_set'].add(hops[i]['addr'])
					#记录跳数
					index_hop=int(hops[i]['probe_ttl'])
					scamper_dic['info'][dst]['hop'][index_hop]=hops[i]['addr']
					scamper_dic['info'][dst]['maxhop']=index_hop
					if (int)(hops[i]['probe_ttl']) +1  == int(hops[i+1]['probe_ttl']):
						# print (hops[i]['probe_ttl']),(hops[i+1]['probe_ttl'])
						s=hops[i]['addr']
						d=hops[i+1]['addr']
						if s == jo['dst']:
							print "how it come",jo['dst'],i
						ip_s=socket.ntohl(struct.unpack("I",socket.inet_aton(s))[0])
						ip_d=socket.ntohl(struct.unpack("I",socket.inet_aton(d))[0])
						if ip_s>ip_d:
							str_ip=d+" "+s
						else:
							str_ip=s+" "+d
						scamper_dic['link_set'].add(str_ip)
						# strace_all_link.add(str_ip)
					#endif
				#记录最后一个节点
				# strace_all_node.add(hops[len_hops-1]['addr'])
				scamper_dic['node_set'].add(hops[len_hops-1]['addr'])
				#记录最后一跳
				index_hop=int(hops[len_hops-1]['probe_ttl'])
				scamper_dic['info'][dst]['hop'][index_hop]=hops[len_hops-1]['addr']
				scamper_dic['info'][dst]['maxhop']=index_hop
				#最后是否是路由器
				if hops[len_hops-1]['addr'] !=dst:
					scamper_dic['router_set'].add(hops[len_hops-1]['addr'])
				else:
					scamper_dic['TARGET_ARRIVE']+=1
	fr.close()
	# for dst in dst_set:
	# 	if dst in node_set:
	# 		node_set.remove(dst)
	if len(scamper_dic['link_set'])==0 or len(scamper_dic['node_set'])==0:
		scamper_dic['broken']=1
		print "!!!!!!!!!!!!!!!!!!!",sfile,"no any data in file!!!!!!!!!!!!!!!"
		return scamper_dic

	scamper_dic['src']=src
	scamper_dic['ALL_NODE']=len(scamper_dic['node_set'])	
	scamper_dic['ALL_LINK']=len(scamper_dic['link_set'])	
	scamper_dic['MID_ROUTER_COUNT']=len(scamper_dic['router_set'])
	print "\n>scamper"
	print "src",scamper_dic['src']
	print "ALL_TARGET",scamper_dic['ALL_TARGET']
	print "ALL_SEND_PACKET",scamper_dic['ALL_SEND_PACKET']
	print "link_set",len(scamper_dic['link_set'])
	print "node_set",len(scamper_dic['node_set'])
	print "router_set",len(scamper_dic['router_set'])
	print "TARGET_ARRIVE",scamper_dic['TARGET_ARRIVE']
	print "all_hop",scamper_dic['all_hop']
	print "RUNTIME",scamper_dic['RUNTIME']
	# print "RUNTIME",scamper_dic['RUNTIME']
	if scamper_dic['RUNTIME']!=0:
		print "avg send packet",1.0*scamper_dic['ALL_SEND_PACKET']/scamper_dic['RUNTIME']
	if sys.argv[2] == "1":
		fw=open(sys.argv[1]+".link",'w')
		for item in scamper_dic['link_set']:
			fw.write(item+"\n")
		fw.close()

		fw=open(sys.argv[1]+".node",'w')
		for item in scamper_dic['node_set']:
			fw.write(item+"\n")
		fw.close()
	if sys.argv[2] == "csv":
		fw=open(sys.argv[1]+".csv",'w')
		for item in scamper_dic['link_set']:
			fw.write(item.split()[0]+','+item.split()[1]+"\n")
		fw.close()

		fw=open(sys.argv[1]+".node",'w')
		for item in scamper_dic['node_set']:
			fw.write(item+"\n")
		fw.close()
	return scamper_dic
if __name__ == '__main__':
	# get_link_node_from_dir()
	get_scamper_packet_by_file()
