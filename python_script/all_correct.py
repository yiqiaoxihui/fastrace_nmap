# -*- coding: utf-8 -*-
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
import networkx as nx
global bnp_sum,fastrace_all_target,all_fastrace_send,all_fastrace_rebund

def get_fastrace_packet_by_file(ffile):
	global ftrace_all_link,ftrace_all_node,ftrace_all_router
	global strace_all_node,strace_all_link,strace_all_router
	global bnp_sum,fastrace_all_target,all_fastrace_send,all_fastrace_rebund
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
	fastrace_dic['DEGREE_ONE']=0.0
	fastrace_dic['DEGREE_BIG']=0.0
	fastrace_dic['DEGREE']=0.0
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
	print "ALL_TARGET",fastrace_dic['ALL_TARGET']
	# print "broken",fastrace_dic['broken']
	# print "BNP_COUNT",fastrace_dic['BNP_COUNT']
	# print "NNS_COUNT",fastrace_dic['NNS_COUNT']
	
	# print "ALL_SEND_PACKET",fastrace_dic['ALL_SEND_PACKET']
	# print "ALL_NODE",fastrace_dic['ALL_NODE']
	# print "ALL_LINK",fastrace_dic['ALL_LINK']
	# print "MID_ROUTER_COUNT",fastrace_dic['MID_ROUTER_COUNT']
	# print "link_set",len(fastrace_dic['link_set'])
	# print "node_set",len(fastrace_dic['node_set'])
	# print "router_set",len(fastrace_dic['router_set'])
	# print "router/link",len(fastrace_dic['router_set'])*1.0/len(fastrace_dic['node_set'])
	# print "TARGET_ARRIVE",fastrace_dic['TARGET_ARRIVE']
	# print "BNP_REDUNDANCE_COUNT",fastrace_dic['BNP_REDUNDANCE_COUNT']
	# print "BNP_COUNT",fastrace_dic['BNP_COUNT']
	# print "NNS_COUNT",fastrace_dic['NNS_COUNT']
	# print "all_hop",fastrace_dic['all_hop']
	# print "RUNTIME",fastrace_dic['RUNTIME']
	# if fastrace_dic['ALL_SEND_PACKET']>0:
	# 	fastrace_dic['BNP_REDUNDANCE_RATE']=fastrace_dic['BNP_REDUNDANCE_COUNT']*1.0/(fastrace_dic['ALL_SEND_PACKET']+fastrace_dic['BNP_REDUNDANCE_COUNT'])
	# 	print "rebundary rate:",fastrace_dic['BNP_REDUNDANCE_RATE']
	# for dst in fastrace_dic['info']:
	# 	fastrace_dic['MAX_HOP_AVG']+=fastrace_dic['info'][dst]['maxhop']
	# 	fastrace_dic['BNP_AVG']+=fastrace_dic['info'][dst]['bnp']
	# fastrace_dic['MAX_HOP_AVG']	=fastrace_dic['MAX_HOP_AVG']*1.0/fastrace_dic['ALL_TARGET']
	# fastrace_dic['BNP_AVG']		=fastrace_dic['BNP_AVG']*1.0/fastrace_dic['ALL_TARGET']
	# print "MAX_HOP_AVG",fastrace_dic['MAX_HOP_AVG']
	# print "BNP_AVG",fastrace_dic['BNP_AVG'],(fastrace_dic['BNP_AVG']-1)*1.0/fastrace_dic['MAX_HOP_AVG']

	return fastrace_dic
def get_scamper_packet_by_file(sfile):
	hops={}
	global ftrace_all_link,ftrace_all_node,ftrace_all_router
	global strace_all_node,strace_all_link,strace_all_router
	global all_scamper_send,all_fastrace_send
	global scamper_all_target,fastrace_all_target
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
	scamper_dic['DEGREE_ONE']=0.0
	scamper_dic['DEGREE_BIG']=0.0
	scamper_dic['DEGREE']=0.0
	scamper_dic['MAX_DEGREE']=0.0
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
	# print "ALL_TARGET",scamper_dic['ALL_TARGET']
	# print "ALL_SEND_PACKET",scamper_dic['ALL_SEND_PACKET']
	# print "link_set",len(scamper_dic['link_set'])
	# print "node_set",len(scamper_dic['node_set'])
	# print "router/link",len(scamper_dic['router_set'])*1.0/len(scamper_dic['node_set'])
	# print "router_set",len(scamper_dic['router_set'])
	# print "TARGET_ARRIVE",scamper_dic['TARGET_ARRIVE']
	# print "all_hop",scamper_dic['all_hop']
	# print "RUNTIME",scamper_dic['RUNTIME']
	# # print "RUNTIME",scamper_dic['RUNTIME']
	# if scamper_dic['RUNTIME']!=0:
	# 	print "avg send packet",1.0*scamper_dic['ALL_SEND_PACKET']/scamper_dic['RUNTIME']
	return scamper_dic

def every_cmp_correct(fastrace_dic,scamper_dic):
	both_have_all_hop=0
	both_have_same_hop=0
	fastrace_no_hop=0
	because_of_bnp=0
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
						else:
							pass
							# print dst,"fastrace not in scamper on ttl",i,fastrace_dic[dst]['hop'][i],hops[i]
						pass
						# print dst,"fastrace not in scamper on ttl",i,fastrace_dic[dst]['hop'][i],hops[i]
						# return 0
					pass
				else:
					fastrace_no_hop+=1
					# print dst,"fastrace_dic not reply at ttl",i
			except Exception as e:
				print "fastrace not has dst key",e
				# for dst in fastrace_dic['info']:
				# 	print "fastrace why",dst
				# for dst in scamper_dic['info']:
				# 	print "scamper_dic why",dst
				# exit(0)
	diff_hop=both_have_all_hop - both_have_same_hop
	because_of_bnp_rate=0
	both_have_same_hop_rate=0
	print "\n>fastrace no hop count",fastrace_no_hop
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
def all_correct():
	froot=sys.argv[1]
	i=0
	j=0
	k=0
	r1=0.0
	r2=0.0
	r3=0.0
	data_number=0
	fw=open('correct.csv','w')
	for dirpath, dirnames, filenames in os.walk(froot):
		# for filepath in filenames:
		#     print os.path.join(dirpath, filepath)
		for dirname in dirnames:
			# print dirname
			# print dirpath
			ffile4="test-fastrace4/"+dirname+"/test-fastrace4.fastrace"
			ffile9="test-fastrace5/"+dirname+"/test-fastrace5.fastrace"
			sfile="test-fastrace-scamper/"+dirname+"/test-fastrace-scamper.json"
			print "-----------------"
			if os.path.exists(ffile4):
				i+=1
				if os.path.exists(ffile9):
					j+=1
					# print ffile
					# get_fastrace_packet_by_file(ffile)
					# get_scamper_packet_by_file(sfile)
					if os.path.exists(sfile):
						print sfile
						print ffile4
						print ffile9
						# get_fastrace_packet_by_file(ffile)
						fastrace_dic4=get_fastrace_packet_by_file(ffile4)
						fastrace_dic9=get_fastrace_packet_by_file(ffile9)
						if fastrace_dic4['broken']!=1 and fastrace_dic9['broken']!=1:
							scamper_dic=get_scamper_packet_by_file(sfile)
							if scamper_dic['ALL_TARGET']!=fastrace_dic4['ALL_TARGET'] or fastrace_dic9['ALL_TARGET'] != scamper_dic['ALL_TARGET']:
								print ">>>>>>>>>>>>>>>>>>",scamper_dic['ALL_TARGET'],fastrace_dic4['ALL_TARGET'],fastrace_dic9['ALL_TARGET']
								continue
							if len(scamper_dic['link_set'])==0 or len(fastrace_dic4['link_set'])==0 or len(fastrace_dic9['link_set'])==0:
								print "^^^^^^^^^^^^^link count not same",len(scamper_dic['link_set']),len(fastrace_dic4['link_set']) ,len(fastrace_dic9['link_set'])
								continue

							print data_number
							data_number+=1
							bnp_arr=every_cmp_correct(fastrace_dic4,scamper_dic)
							bnp_icmp_arr=every_cmp_correct(fastrace_dic9,scamper_dic)
							r1+=bnp_arr[2]
							r2+=bnp_arr[1]
							r3+=bnp_icmp_arr[1]
							fw.write(str(bnp_arr[2])+","+str(bnp_arr[1])+","+str(bnp_icmp_arr[1])+"\n")
						else:
							print "<<<<<<<<<<<<<<<<<<<",fastrace_dic4['ALL_TARGET'],fastrace_dic9["ALL_TARGET"]
					else:
						print sfile,"scamper not exists"
				else:
					print ffile9,"f9 not exists"
			else:
				print ffile4,"f4 not exists"
	fw.close()
	print r1/data_number,r2/data_number,r3/data_number
if __name__ == '__main__':
	global bnp_sum,fastrace_all_target,scamper_all_target
	global all_bnp_avg_len,all_fastrace_max_hop_avg_len,bnp_avg_in_max_hop
	global all_fastrace_send,all_fastrace_rebund,all_scamper_send
	global ftrace_all_link,ftrace_all_node,ftrace_all_router
	global strace_all_node,strace_all_link,strace_all_router
	global fastrace_degree_dic
	ftrace_all_node=set()
	ftrace_all_link=set()
	ftrace_all_router=set()
	strace_all_router=set()
	strace_all_node=set()
	strace_all_link=set()

	fastrace_degree_dic={}
	bnp_sum=0
	fastrace_all_target=0
	scamper_all_target=0
	all_fastrace_send=0
	all_fastrace_rebund=0
	all_scamper_send=0
	bnp_avg_in_max_hop=0
	all_fastrace_max_hop_avg_len=0
	all_bnp_avg_len=0

	all_correct()
		# runpath()
