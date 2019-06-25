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
import matplotlib.pyplot as plt 

global nbp_sum,all_dst_sum,all_dst_packet,all_dst_rebund
def get_fastrace_second():
	all_ip=0
	frf=open(sys.argv[2],'r')
	ftrace={}
	# line=frf.readline()
	# if not line:
	# 	print("file in empty")
	# 	return
	line=frf.readline()
	while True:
		# pline=line
		if "Target" in line:
			all_ip+=1
			dst=line.split()[1]
			ftrace[dst]={}
			if len(line.split())>=13:
				ftrace[dst]['bnp']=int(line.split()[9])
			# print ftrace[dst]['bnp']
			ftrace[dst]['hop']={}
			line=frf.readline()
			i=1 			#ttl from 1 for fastrace
			# print "Target",dst
			while line[0]=="~":
				# print i,line.split()[2]
				if line.split()[2] != "0":
					ftrace[dst]['hop'][i]=line.split()[2]
				line=frf.readline()
				i+=1
				if not line:
					break
			while "Target" not in line:
				line=frf.readline()
				if not line:
					break
		if not line:
			break
	frf.close()
	print all_ip
	return ftrace


def cmp_ftrace_self_correct():
	ftrace=get_fastrace()
	strace=get_fastrace_second()
	all_hop=0
	all_same_hop=0
	fastrace_no_hop=0
	for dst in strace:
		trace=strace[dst]
		hops=trace['hop']
		for i in hops:
			if ftrace[dst]['hop'].has_key(i):
				all_hop+=1
				if ftrace[dst]['hop'][i] == hops[i]:
					# print ftrace[dst]['hop'][i] , hops[i]
					all_same_hop+=1
				else:
					print dst,"fastrace not in scamper on ttl",i,ftrace[dst]['hop'][i],hops[i]
			else:
				fastrace_no_hop+=1
				print "ftrace:",len(ftrace[dst]['hop']),'strace:',i

	print "fastrace no hop count",fastrace_no_hop
	print "all_hop,all_same_hop",all_hop, all_same_hop
	if all_hop>0:
		print all_same_hop*1.0/all_hop

def get_scamper_first():
	all_ip=0
	frs=open(sys.argv[1],'r')
	strace={}
	while True:
		line = frs.readline().strip()
		if not line:
			break
		else:
			all_ip+=1
			jo=json.loads(line)
			if jo.has_key('dst')==False:
				continue
			dst=jo['dst']
			strace[dst]={}
			strace[dst]['hop']={}
			if jo.has_key('hops'):
				hops=jo['hops']
				for hop in hops:
					strace[dst]['hop'][int(hop['probe_ttl'])]=hop['addr']
					# print hop['probe_ttl'],hop['addr']	
	frs.close()
	print "scamper",all_ip
	return strace
def cmp_scamper_self_correct():
	ftrace=get_scamper()
	strace=get_scamper_first()
	all_hop=0
	all_same_hop=0
	fastrace_no_hop=0
	for dst in strace:
		trace=strace[dst]
		hops=trace['hop']
		for i in hops:
			if ftrace[dst]['hop'].has_key(i):
				all_hop+=1
				if ftrace[dst]['hop'][i] == hops[i]:
					# print ftrace[dst]['hop'][i] , hops[i]
					all_same_hop+=1
				else:
					print dst,"fastrace not in scamper on ttl",i,ftrace[dst]['hop'][i],hops[i]
			else:
				fastrace_no_hop+=1
				print "ftrace:",len(ftrace[dst]['hop']),'strace:',i

	print "fastrace no hop count",fastrace_no_hop
	print "all_hop,all_same_hop",all_hop, all_same_hop
	if all_hop>0:
		print all_same_hop*1.0/all_hop




def get_fastrace():
	all_ip=0
	all_hop=0
	frf=open(sys.argv[1],'r')
	ftrace={}
	line=frf.readline()
	while True:
		# pline=line
		if "Target" in line:
			all_ip+=1
			dst=line.split()[1]
			ftrace[dst]={}
			if len(line.split())>=13:
				ftrace[dst]['bnp']=int(line.split()[-1])
			# print ftrace[dst]['bnp']
			ftrace[dst]['hop']={}
			ftrace[dst]['maxhop']=0
			line=frf.readline()
			i=1 			#ttl from 1 for fastrace
			# print "Target",dst
			if not line:
				break
			while line[0]=="~":
				# print i,line
				if len(line.split())< 3:
					print "ftrace not complete"
					return ftrace
				if line.split()[2] != "0":
					all_hop+=1
					ftrace[dst]['hop'][i]=line.split()[2]
					ftrace[dst]['maxhop']=i
				line=frf.readline().strip()
				i+=1
			while "Target" not in line:
				line=frf.readline()
				if not line:
					break

		if not line:
			break
	frf.close()
	print "fastrace,all_hop",all_ip,all_hop
	return ftrace
def get_scamper():
	all_ip=0
	all_hop=0
	frs=open(sys.argv[2],'r')
	strace={}
	while True:
		line = frs.readline().strip()
		if not line:
			break
		else:
			jo=json.loads(line)
			if jo.has_key('dst')==False:
				continue
			all_ip+=1
			dst=jo['dst']
			strace[dst]={}
			strace[dst]['maxhop']=0
			strace[dst]['hop']={}
			if jo.has_key('hops'):
				hops=jo['hops']
				for hop in hops:
					all_hop+=1
					strace[dst]['hop'][int(hop['probe_ttl'])]=hop['addr']
					strace[dst]['maxhop']=int(hop['probe_ttl'])
					# print hop['probe_ttl'],hop['addr']	
	frs.close()
	print "scamper,all_hop",all_ip,all_hop
	return strace
def get_fastrace_by_file(ffile):
	global ftrace_all_node,ftrace_all_link,strace_all_node,strace_all_link
	all_ip=0
	all_hop=0
	frf=open(ffile,'r')
	ftrace={}
	line=frf.readline()
	node=0
	link=0
	router_set=set()
	avg_maxhop=0
	avg_bnp=0
	while True:
		# pline=line
		if "Target" in line:
			all_ip+=1
			dst=line.split()[1]
			ftrace[dst]={}
			ftrace[dst]['bnp']=0
			ftrace[dst]['hop']={}
			ftrace[dst]['maxhop']=0
			if len(line.split())>=13:
				ftrace[dst]['bnp']=int(line.split()[9])
			# print ftrace[dst]['bnp']
			line=frf.readline()
			i=1 			#ttl from 1 for fastrace
			# print "Target",dst
			if not line:
				break
			while line[0]=="~":
				# print i,line.split()[2]
				if len(line.split())<3:
					print "ftrace no complete"
					return ftrace
				if line.split()[2] != "0":
					all_hop+=1
					ftrace_all_node.add(line.split()[2])
					if dst != line.split()[2]:
						router_set.add(line.split()[2])
					ftrace[dst]['hop'][i]=line.split()[2]
					ftrace[dst]['maxhop']=i
				line=frf.readline()
				i+=1
				if not line:
					break
			while "Target" not in line:
				if "ALL_LINK" in line:
					link=int(line.split()[1])
				if "ALL_NODE" in line:
					node=int(line.split()[1])
				line=frf.readline()
				if not line:
					break
		if not line:
			break
	frf.close()
	if len(ftrace)<4096:
		return ftrace
	for dst in ftrace:
		avg_maxhop+= ftrace[dst]['maxhop']
		avg_bnp+= ftrace[dst]['bnp']
	avg_maxhop=avg_maxhop*1.0/len(ftrace)
	avg_bnp=avg_bnp*1.0/len(ftrace)

	print "fastrace,all_hop,link,node,router",all_ip,all_hop,link,node,len(router_set)
	if avg_maxhop>0:
		print "fastrace avg_maxhop,avg_bnp",avg_maxhop,avg_bnp,avg_bnp*1.0/avg_maxhop
	return ftrace
def get_scamper_by_file(sfile):
	all_ip=0
	frs=open(sfile,'r')
	strace={}
	all_hop=0
	link_set=set()
	node_set=set()
	router_set=set()
	while True:
		line = frs.readline()
		if not line:
			break
		else:
			jo=json.loads(line)
			if jo.has_key('dst')==False:
				continue
			all_ip+=1
			dst=jo['dst']
			strace[dst]={}
			strace[dst]['maxhop']=0
			strace[dst]['hop']={}
			if jo.has_key('hops'):
					hops=jo['hops']
					len_hops=len(hops)
					if len_hops<=0:
						continue
					if int(hops[0]['probe_ttl'])==1:
						link_set.add(jo['src']+" "+hops[0]['addr'])
					for i in range(0,len_hops-1):
						router_set.add(hops[i]['addr']) #路由器
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
						all_hop+=1
						#每一跳
						strace[dst]['hop'][int(hops[i]['probe_ttl'])]=hops[i]['addr']
						strace[dst]['maxhop']=int(hops[i]['probe_ttl'])
					#最后一个节点
					node_set.add(hops[len_hops-1]['addr'])
					all_hop+=1
					strace[dst]['hop'][int(hops[len_hops-1]['probe_ttl'])]=hops[len_hops-1]['addr']
					strace[dst]['maxhop']=int(hops[len_hops-1]['probe_ttl'])
					#最后一条
					if hops[len_hops-1]['addr'] !=jo['dst']:
						router_set.add(hops[len_hops-1]['addr'])
					# print hop['probe_ttl'],hop['addr']	发现路由器数量，发包数量
	frs.close()
	print "scamper,hop,link,node,router",all_ip,all_hop,len(link_set),len(node_set),len(router_set)
	return strace
def get_all_scamper():
	all_ip=0
	strace={}
	i=0
	for filename in os.listdir(sys.argv[2]):
		if ".json" == filename[-5:]:
			i+=1
			if i > int(sys.argv[4]):
				break
			print "scamper file",sys.argv[2]+filename
			frs=open(sys.argv[2]+filename,'r')
			while True:
				line = frs.readline().strip()
				if not line:
					break
				else:
					jo=json.loads(line)
					if jo.has_key('dst')==False:
						continue
					dst=jo['dst']
					if strace.has_key(dst) ==False:
						strace[dst]={}
						strace[dst]['hop']={}
						all_ip+=1

					if jo.has_key('hops'):
						hops=jo['hops']
						for hop in hops:
							ttl=int(hop['probe_ttl'])
							if strace[dst]['hop'].has_key(ttl):
								strace[dst]['hop'][ttl].add(hop['addr'])
							else:
								strace[dst]['hop'][ttl]=set()
								strace[dst]['hop'][ttl].add(hop['addr'])
							# print hop['probe_ttl'],hop['addr']	
			frs.close()
	print "scamper,link,node,router",all_ip

	return strace
def mutil_cmp_correct():
	ftrace=get_fastrace()
	strace=get_all_scamper()
	all_hop=0
	all_same_hop=0
	diff_hop=0
	fastrace_no_hop=0
	because_of_bnp=0
	sum_hop=0
	for dst in strace:
		trace=strace[dst]
		hops=trace['hop']
		for i in hops:
			sum_hop+=1
			# if i >= ftrace[dst]['bnp']:
				#fastrace also has this hop
			if ftrace[dst]['hop'].has_key(i):
				all_hop+=1
				if ftrace[dst]['hop'][i] in hops[i]:
					# print ftrace[dst]['hop'][i] , hops[i]
					all_same_hop+=1
				else:
					pass
					if ftrace[dst].has_key('bnp') and ftrace[dst]['bnp'] > i:
						because_of_bnp+=1
					print dst,"fastrace not in scamper on ttl:",i,
					if ftrace[dst].has_key('bnp'):
						print ", BNP:",ftrace[dst]['bnp'],
					print ftrace[dst]['hop'][i]
					# for t in hops[i]:
					# 	print t,
					# print "\n"
			else:
				fastrace_no_hop+=1
				# print dst,"ftrace no this hop ttl",i
	diff_hop=all_hop - all_same_hop
	print "sum_hop",sum_hop
	print "fastrace no hop count",fastrace_no_hop,fastrace_no_hop*1.0/sum_hop
	print "all_hop,all_same_hop",all_hop, all_same_hop
	print "different hop, because_of_bnp:",diff_hop,because_of_bnp,
	if diff_hop!=0:
		print because_of_bnp*1.0/diff_hop
	if all_hop>0:
		print all_same_hop*1.0/all_hop

def cmp_correct_single():
	ftrace=get_fastrace()
	strace=get_scamper()
	both_have_all_hop=0
	both_have_same_hop=0
	fastrace_no_hop=0
	because_of_bnp=0
	if len(ftrace) != len(strace):
		print "ip not same"
		return 0
	for dst in strace:
		trace=strace[dst]
		hops=trace['hop']
		for i in hops:
			# print dst
			try:
				if ftrace[dst]['hop'].has_key(i):
					both_have_all_hop+=1
					if ftrace[dst]['hop'][i] == hops[i]:
						# print i,ftrace[dst]['hop'][i] , hops[i]
						both_have_same_hop+=1
					else:
						if ftrace[dst].has_key('bnp') and ftrace[dst]['bnp'] > i:
							because_of_bnp+=1
						else:
							print dst,i,ftrace[dst]['hop'][i],hops[i],"fastrace not in scamper on ttl"
						pass
				else:
					fastrace_no_hop+=1
					# print dst,"ftrace not reply at ttl",i
			except Exception as e:
				# print "fastrace incomplete",e
				break
	diff_hop=both_have_all_hop - both_have_same_hop
	print "fastrace no hop count",fastrace_no_hop
	print "both_have_all_hop,both_have_same_hop",both_have_all_hop, both_have_same_hop
	print "different hop, because_of_bnp:",diff_hop,because_of_bnp,
	because_of_bnp_rate=0
	both_have_same_hop_rate=0
	if diff_hop!=0:
		because_of_bnp_rate=because_of_bnp*1.0/diff_hop
		print because_of_bnp_rate
	else:
		print "\n"
	if both_have_all_hop !=0:
		both_have_same_hop_rate=both_have_same_hop*1.0/both_have_all_hop
		print "RATE: ",both_have_same_hop_rate
	thoery_both_have_rate=(1- both_have_same_hop_rate )*because_of_bnp_rate +both_have_same_hop_rate
	print "thoery_both_have_rate",thoery_both_have_rate
	r={}
	r[1]=thoery_both_have_rate
	r[2]=both_have_same_hop_rate
	r[3]=(1- both_have_same_hop_rate )*because_of_bnp_rate
	r[4]=both_have_all_hop
	return r 
def get_fastrace_packet_by_file(ffile):
	global ftrace_all_node,ftrace_all_link,strace_all_node,strace_all_link
	global ftrace_all_router
	fr=open(ffile,'r')
	ALL_SEND_PACKET=0
	ALL_TARGET=0
	ALL_NODE=0
	ALL_LINK=0
	ALL_TARGET=0
	BNP_REDUNDANCE_COUNT=0
	result={}
	router=0
	result['packet']=ALL_SEND_PACKET
	result['link']=ALL_LINK
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
		return result
	while True:
		pline=line
		line=fr.readline()
		if not line:
			break
		if "ALL_SEND_PACKET" in line:
			ALL_SEND_PACKET=int(line.split()[1])
		if "ALL_NODE" in line:
			ALL_NODE=line.split()[1]
		if "ALL_LINK" in line:
			ALL_LINK=int(line.split()[1])
		if "BNP_REDUNDANCE_COUNT" in line:
			BNP_REDUNDANCE_COUNT=int(line.split()[1])
		if "BNP_COUNT" in line:
			BNP_COUNT=int(line.split()[1])
		if "ALL_TARGET" in line:
			ALL_TARGET=int(line.split()[1])	
		if "NNS_COUNT" in line:
			NNS_COUNT=line.split()[1]	
		if "Target" in pline:
			if len(pline.split())>7:
				dst= pline.split()[1]
				dst_set.add(dst)
				src=pline.split()[7]
				if line[0] == '~':
					link_set.add(src+" "+line.split()[2])
					ftrace_all_link.add(src+" "+line.split()[2])
			else:
				return result
		if pline[0] == '~' and len(pline.split())>3:
			node_set.add(pline.split()[2])
			ftrace_all_node.add(pline.split()[2])
			if pline.split()[2]!=dst:
				mid_router_set.add(pline.split()[2])
				ftrace_all_router.add(pline.split()[2])
		if line[0] == '~' and len(line.split())>3:
			ftrace_all_node.add(line.split()[2])
			node_set.add(line.split()[2])
			if line.split()[2]!=dst:
				mid_router_set.add(line.split()[2])
				ftrace_all_router.add(line.split()[2])
		if "Got there" in line:
			reply_dst_set.add(line.split()[1])
		if pline[0] == '~' and line[0] == '~':
			if len(pline.split())>3 and len(line.split())>3:
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
				ftrace_all_link.add(str_ip)
				if d==dst:
					dst_link_count+=1

	print "fastrace"
	print "dst sum",ALL_TARGET
	if ALL_SEND_PACKET == 0:
		return result
	print "ALL_SEND_PACKET",ALL_SEND_PACKET
	print "BNP_REDUNDANCE_COUNT",BNP_REDUNDANCE_COUNT
	print "rebundary rate:",BNP_REDUNDANCE_COUNT*1.0/ALL_SEND_PACKET
	print "ALL_LINK,ALL_NODE,router",ALL_LINK,ALL_NODE,len(mid_router_set)
	print "BNP_COUNT",BNP_COUNT
	print "NNS_COUNT",NNS_COUNT
	# print BNP_REDUNDANCE_COUNT/ALL_SEND_PACKET
	global nbp_sum,all_dst_sum,all_dst_packet,all_dst_rebund
	nbp_sum+=BNP_COUNT
	all_dst_sum+=ALL_TARGET
	all_dst_packet+=ALL_SEND_PACKET
	all_dst_rebund+=BNP_REDUNDANCE_COUNT
	result['packet']=ALL_SEND_PACKET
	result['link']=ALL_LINK
	return result
def get_scamper_packet_by_file(sfile):
	hops={}
	global ftrace_all_node,ftrace_all_node,strace_all_node,strace_all_link
	# list_dir = os.listdir(file_dir)
	link_set=set()
	node_set=set()
	all_packet=0
	all_time=0
	dst_set=set()
	all_ip=0
	# for file in list_dir:

	fr=open(sfile,'r')
	# print file
	global all_scamper_send
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
					strace_all_link.add(jo['src']+" "+hops[0]['addr'])
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
						strace_all_link.add(str_ip)
					strace_all_node.add(hops[i]['addr'])
					node_set.add(hops[i]['addr'])
				strace_all_node.add(hops[len_hops-1]['addr'])
				node_set.add(hops[len_hops-1]['addr'])
	fr.close()
	# for dst in dst_set:
	# 	if dst in node_set:
	# 		node_set.remove(dst)
	print "scamper"
	print "dst sum",len(dst_set)
	print "all link",len(link_set),"all node",len(node_set),"all_packet",all_packet
	print "all time",all_time
	if all_time!=0:
		print "avg send packet",1.0*all_packet/all_time
	d={}
	all_scamper_send+=all_packet
	d['packet']=all_packet
	d['link']=len(link_set)
	return d
def every_packet_rate(ffile,sfile):
	fr=get_fastrace_packet_by_file(ffile)
	sr=get_scamper_packet_by_file(sfile)
	if sr['link']!=0 and sr['packet']!=0:
		print "link rate",fr['link']*1.0/sr['link']
		print "packet rate",fr['packet']*1.0/sr['packet']
def every_cmp_correct(ffile,sfile):
	ftrace=get_fastrace_by_file(ffile)
	strace=get_scamper_by_file(sfile)
	both_have_all_hop=0
	both_have_same_hop=0
	fastrace_no_hop=0
	because_of_bnp=0
	if len(ftrace) != len(strace):
		print "ip not same"
		return 0
	for dst in strace:
		trace=strace[dst]
		hops=trace['hop']
		for i in hops:
			try:
				if ftrace[dst]['hop'].has_key(i):
					both_have_all_hop+=1
					if ftrace[dst]['hop'][i] == hops[i]:
						# print i,ftrace[dst]['hop'][i] , hops[i]
						both_have_same_hop+=1
					else:
						if ftrace[dst].has_key('bnp') and ftrace[dst]['bnp'] > i:
							because_of_bnp+=1
						pass
						# print dst,"fastrace not in scamper on ttl",i,ftrace[dst]['hop'][i],hops[i]
						# return 0
				else:
					fastrace_no_hop+=1
					# print dst,"ftrace not reply at ttl",i
			except Exception as e:
				# print "fastrace incomplete",e
				break
	diff_hop=both_have_all_hop - both_have_same_hop
	print "fastrace no hop count",fastrace_no_hop
	print "both_have_all_hop,both_have_same_hop",both_have_all_hop, both_have_same_hop
	print "different hop, because_of_bnp:",diff_hop,because_of_bnp,
	because_of_bnp_rate=0
	both_have_same_hop_rate=0
	if diff_hop!=0:
		because_of_bnp_rate=because_of_bnp*1.0/diff_hop
		print because_of_bnp_rate
	else:
		print "\n"
	if both_have_all_hop !=0:
		both_have_same_hop_rate=both_have_same_hop*1.0/both_have_all_hop
		print "RATE: ",both_have_same_hop_rate
	thoery_both_have_rate=(1- both_have_same_hop_rate )*because_of_bnp_rate +both_have_same_hop_rate
	print "thoery_both_have_rate",thoery_both_have_rate
	r={}
	r[1]=thoery_both_have_rate
	r[2]=both_have_same_hop_rate
	r[3]=(1- both_have_same_hop_rate )*because_of_bnp_rate
	r[4]=both_have_all_hop
	return r 

def cmp_correct150():
	global nbp_sum,all_dst_sum,all_dst_packet,all_dst_rebund
	global ftrace_all_node,ftrace_all_link,strace_all_node,strace_all_link
	sroot=sys.argv[2]
	froot=sys.argv[1]
	x=[]
	thoery_y=[]
	both_y=[]
	bnp_y=[]
	i=1
	useful_data=0
	for dirpath, dirnames, filenames in os.walk(froot):
		# for filepath in filenames:
		#     print os.path.join(dirpath, filepath)
		for dirname in dirnames:
			# print dirname
			# print dirpath
			ffile=dirpath+dirname+"/test-fastrace4.fastrace"
			if os.path.exists(ffile):
				# print sfile
				sfile=sroot+dirname+"/test-fastrace-scamper.json"
				if os.path.exists(sfile):
					print "----------------------"
					print sfile
					print dirpath+dirname
					every_packet_rate(ffile,sfile)
					r=every_cmp_correct(ffile,sfile)
					if r!=0 and r[1]  > 0.01:
						i+=1
						x.append(i)
						thoery_y.append(r[1])
						both_y.append(r[2])
						bnp_y.append(r[3])

			else:
				pass
				print "ftrace data no exist",dirname
	print "nbp_sum",nbp_sum
	print "all_dst_sum",all_dst_sum,nbp_sum*1.0/all_dst_sum

	print "all_dst_packet",all_dst_packet 		#fastrace 
	print "all_dst_rebund",all_dst_rebund,all_dst_packet+all_dst_rebund,all_dst_rebund*1.0/(all_dst_packet+all_dst_rebund)
	print "scamper packet",all_scamper_send, all_dst_packet*1.0/all_scamper_send
	print "ftrace_all_node,ftrace_all_link,strace_all_node,strace_all_link"
	print len(ftrace_all_node),len(ftrace_all_link),len(strace_all_node),len(strace_all_link)
	print "ftrace_all_router",len(ftrace_all_router),len(ftrace_all_router)*1.0/len(ftrace_all_node)
	only_strace_ip=strace_all_node.difference(ftrace_all_node)
	only_ftrace_ip=ftrace_all_node.difference(strace_all_node)
	print "only_strace_ip,only_ftrace_ip"
	print len(only_strace_ip),len(only_ftrace_ip)

	# fw=open("only_strace_ip",'w')
	# for ip in only_strace_ip:
	# 	fw.write(ip+"\n")
	# fw.close()
	# fw=open("only_ftrace_ip",'w')
	# for ip in only_ftrace_ip:
	# 	fw.write(ip+"\n")
	# fw.close()
	# draw(x,thoery_y,both_y,bnp_y)
def draw(x1,y1,y2,y3):
	#plt.plot(x1,y1,label='router')#,linewidth=3,color='r',marker='o', markerfacecolor='blue',markersize=12 
	plt.plot(x1,y1,label='') 
	plt.plot(x1,y3,label='') 
	plt.plot(x1,y2,label='') 
	# ya=[]
	# i=0.00
	# for a in range(0,11):
	# 	ya.append(i)
	# 	i+=0.1
	# plt.yticks(ya)
	plt.xlabel('') 
	plt.ylabel('') 
	plt.title('') 
	plt.legend() 
	plt.show() 
if __name__ == '__main__':
	global nbp_sum,all_dst_sum,all_dst_packet,all_dst_rebund,all_scamper_send
	global ftrace_all_node,ftrace_all_link,strace_all_node,strace_all_link
	global ftrace_all_router
	ftrace_all_router=set()
	ftrace_all_node=set()
	ftrace_all_link=set()
	strace_all_node=set()
	strace_all_link=set()

	nbp_sum=0
	all_dst_sum=0
	all_dst_packet=0
	all_dst_rebund=0
	all_scamper_send=0
	# get_fastrace()
	# get_scamper()
	# cmp_correct()
	# get_all_scamper()
	if sys.argv[3] == "m":
		mutil_cmp_correct()
	elif sys.argv[3] == "n":
		cmp_correct_single()
		# every_cmp_correct('test-fastrace2/JP0108/test-fastrace2.fastrace','test-fastrace-scamper/JP0108/test-fastrace-scamper.json')
	elif sys.argv[3]== "s":
		cmp_ftrace_self_correct()
	else:
		pass
		cmp_correct150()
