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

global bnp_sum,all_dst_sum,all_dst_packet,all_dst_rebund

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

def get_fastrace_packet_by_file(ffile):
	global ftrace_all_node,ftrace_all_link,strace_all_node,strace_all_link
	global bnp_sum,all_dst_sum,all_dst_packet,all_dst_rebund
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
	fastrace_dic['BNP_COUNT']=0
	fastrace_dic['NNS_COUNT']=0
	fastrace_dic['RUNTIME']=0
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
		print ffile+": broken!"
		return fastrace_dic
	pline=""
	line=""
	fr.seek(0,0)
	line=fr.readline()
	dst=""
	if not line:
		print("file in empty")
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
				dst= pline.split()[1]
				# print pline
				src=pline.split()[7]
				#记录每一跳
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
						fastrace_dic['MID_ROUTER_COUNT']+=1
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
			print ffile,e
			print pline
			print line
			fastrace_dic['broken']=1
			return fastrace_dic
	ftrace_all_link=ftrace_all_link.union(fastrace_dic['link_set'])
	ftrace_all_node=ftrace_all_node.union(fastrace_dic['node_set'])
	fastrace_dic['src']=src
	print "fastrace"
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
		print "rebundary rate:",fastrace_dic['BNP_REDUNDANCE_COUNT']*1.0/fastrace_dic['ALL_SEND_PACKET']
	
	bnp_sum+=fastrace_dic['BNP_COUNT']
	all_dst_sum+=fastrace_dic['ALL_TARGET']
	all_dst_packet+=fastrace_dic['ALL_SEND_PACKET']
	all_dst_rebund+=fastrace_dic['BNP_REDUNDANCE_COUNT']
	return fastrace_dic
def get_scamper_packet_by_file(sfile):
	hops={}
	global ftrace_all_node,ftrace_all_node,strace_all_node,strace_all_link
	global all_scamper_send
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
	link_set=set()
	node_set=set()
	all_packet=0
	all_time=0
	dst_set=set()
	all_ip=0
	# for file in list_dir:
	fr=open(sfile,'r')
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
				scamper_dic['RUNTIME']=(stop_time-start_time)
			if jo.has_key('dst')==False:
				continue
			scamper_dic['ALL_TARGET']+=1
			if jo.has_key('probe_count'):
				scamper_dic['ALL_SEND_PACKET']+=int(jo['probe_count'])
			dst=jo['dst']
			src=jo['src']
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
					s=dst
					d=hops[0]['addr']
					ip_s=socket.ntohl(struct.unpack("I",socket.inet_aton(s))[0])
					ip_d=socket.ntohl(struct.unpack("I",socket.inet_aton(d))[0])
					if ip_s>ip_d:
						str_ip=d+" "+s
					else:
						str_ip=s+" "+d
					scamper_dic['link_set'].add(str_ip)
					strace_all_link.add(str_ip)
				for i in range(0,len_hops-1):
					#节点
					strace_all_node.add(hops[i]['addr'])
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
						strace_all_link.add(str_ip)
					#endif
				#记录最后一个节点
				strace_all_node.add(hops[len_hops-1]['addr'])
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

	scamper_dic['src']=src
	scamper_dic['ALL_NODE']=len(scamper_dic['node_set'])	
	scamper_dic['ALL_LINK']=len(scamper_dic['link_set'])	
	scamper_dic['MID_ROUTER_COUNT']=len(scamper_dic['router_set'])
	print "scamper"
	print "fastrace"
	print "src",scamper_dic['src']
	print "ALL_TARGET",scamper_dic['ALL_TARGET']
	print "ALL_SEND_PACKET",scamper_dic['ALL_SEND_PACKET']
	print "link_set",len(scamper_dic['link_set'])
	print "node_set",len(scamper_dic['node_set'])
	print "router_set",len(scamper_dic['router_set'])
	print "TARGET_ARRIVE",scamper_dic['TARGET_ARRIVE']
	print "all_hop",scamper_dic['all_hop']
	print "RUNTIME",scamper_dic['RUNTIME']
	# print "RUNTIME",fastrace_dic['RUNTIME']
	if scamper_dic['RUNTIME']!=0:
		print "avg send packet",1.0*scamper_dic['ALL_SEND_PACKET']/scamper_dic['RUNTIME']
	all_scamper_send+=all_packet

	return scamper_dic
# def every_packet_rate(ffile,sfile):
# 	fastrace_dic=get_fastrace_packet_by_file(ffile)
# 	sr=get_scamper_packet_by_file(sfile)

def every_cmp_correct(ffile,sfile):
	both_have_all_hop=0
	both_have_same_hop=0
	fastrace_no_hop=0
	because_of_bnp=0
	fastrace_dic=get_fastrace_packet_by_file(ffile)
	if fastrace_dic['broken']!=1:
		scamper_dic=get_scamper_packet_by_file(sfile)
	else:
		return 0
	if scamper_dic['ALL_LINK']!=0:
		print "link rate(f/s)",fastrace_dic['ALL_LINK']*1.0/scamper_dic['ALL_LINK']
	if  scamper_dic['ALL_NODE']!=0:
		print "node rate(f/s)",fastrace_dic['ALL_NODE']*1.0/scamper_dic['ALL_NODE']
	if scamper_dic['ALL_SEND_PACKET']!=0:
		print "packet rate(f/s)",fastrace_dic['ALL_SEND_PACKET']*1.0/scamper_dic['ALL_SEND_PACKET']


	if fastrace_dic['ALL_TARGET'] != scamper_dic['ALL_TARGET']:
		print fastrace_dic['file'],fastrace_dic['ALL_TARGET'],scamper_dic['ALL_TARGET'],"ip count not same"
		return 0
	for dst in scamper_dic['info']:
		trace=scamper_dic['info'][dst]
		hops=trace['hop']
		for i in hops:
			try:
				if fastrace_dic['info'][dst]['hop'].has_key(i):
					both_have_all_hop+=1
					if fastrace_dic['info'][dst]['hop'][i] == hops[i]:
						# print i,fastrace_dic[dst]['hop'][i] , hops[i]
						both_have_same_hop+=1
					else:
						if fastrace_dic['info'][dst].has_key('bnp') and fastrace_dic['info'][dst]['bnp'] > i:
							because_of_bnp+=1
						pass
						# print dst,"fastrace not in scamper on ttl",i,fastrace_dic[dst]['hop'][i],hops[i]
						# return 0
				else:
					fastrace_no_hop+=1
					# print dst,"fastrace_dic not reply at ttl",i
			except Exception as e:
				# print "fastrace incomplete",e
				break
	diff_hop=both_have_all_hop - both_have_same_hop
	because_of_bnp_rate=0
	both_have_same_hop_rate=0
	print "fastrace no hop count",fastrace_no_hop
	print "both_have_all_hop,both_have_same_hop",both_have_all_hop, both_have_same_hop
	print "fastrace have but different hop, because_of_bnp:",diff_hop,because_of_bnp,
	if diff_hop!=0:
		because_of_bnp_rate=because_of_bnp*1.0/diff_hop
		print because_of_bnp_rate
	else:
		print "\n"
	if both_have_all_hop !=0:
		both_have_same_hop_rate=both_have_same_hop*1.0/both_have_all_hop
		print "RATE: ",both_have_same_hop_rate
	thoery_both_have_rate=(1- both_have_same_hop_rate )*because_of_bnp_rate + both_have_same_hop_rate
	print "thoery_both_have_rate",thoery_both_have_rate
	r={} 		#记录一致率数据
	r[1]=thoery_both_have_rate
	r[2]=both_have_same_hop_rate
	r[3]=(1- both_have_same_hop_rate )*because_of_bnp_rate
	r[4]=both_have_all_hop
	return r 

def cmp_correct150():
	global bnp_sum,all_dst_sum,all_dst_packet,all_dst_rebund
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
					print ffile
					# every_packet_rate(ffile,sfile)
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

	print "150 bnp_sum",bnp_sum
	print "150 all_dst_sum",all_dst_sum,bnp_sum*1.0/all_dst_sum

	print "150 fastrace all dst_packet",all_dst_packet
	print "150 fastrace all dst_rebund",all_dst_rebund,all_dst_packet+all_dst_rebund,all_dst_rebund*1.0/(all_dst_packet+all_dst_rebund)
	print "150 scamper all packet,f/s",all_scamper_send, all_dst_packet*1.0/all_scamper_send
	print "150 ftrace_all_node,ftrace_all_link,strace_all_node,strace_all_link"
	print len(ftrace_all_node),len(ftrace_all_link),len(strace_all_node),len(strace_all_link)
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
def runpath():
	global bnp_sum,all_dst_sum,all_dst_packet,all_dst_rebund
	global ftrace_all_node,ftrace_all_link,strace_all_node,strace_all_link
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
			sfile=dirpath+dirname+"/test-fastrace-scamper.json"
			print "-----------------"
			
			if os.path.exists(ffile):
				print ffile
				# get_fastrace_packet_by_file(ffile)
				# get_scamper_packet_by_file(sfile)
			if os.path.exists(sfile):
				print sfile
				# get_fastrace_packet_by_file(ffile)
				get_scamper_packet_by_file(sfile)		

if __name__ == '__main__':
	global bnp_sum,all_dst_sum,all_dst_packet,all_dst_rebund,all_scamper_send
	global ftrace_all_node,ftrace_all_link,strace_all_node,strace_all_link
	ftrace_all_node=set()
	ftrace_all_link=set()
	strace_all_node=set()
	strace_all_link=set()

	bnp_sum=0
	all_dst_sum=0
	all_dst_packet=0
	all_dst_rebund=0
	all_scamper_send=0

	if sys.argv[3] == "m":
		mutil_cmp_correct()
	elif sys.argv[3] == "n":
		cmp_correct_single()
		# every_cmp_correct('test-fastrace2/JP0108/test-fastrace2.fastrace','test-fastrace-scamper/JP0108/test-fastrace-scamper.json')
	elif sys.argv[3]== "s":
		cmp_ftrace_self_correct()
	elif sys.argv[3]=="f":
		get_fastrace_packet_by_file(sys.argv[1])
	else:
		pass
		cmp_correct150()
		# runpath()
