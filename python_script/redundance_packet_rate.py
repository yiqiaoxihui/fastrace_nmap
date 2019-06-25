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


def get_fastrace_packet_by_file(ffile):
	fr=open(ffile,'r')
	ALL_SEND_PACKET=0
	ALL_TARGET=0
	ALL_NODE=0
	ALL_LINK=0
	ALL_TARGET=0
	BNP_REDUNDANCE_COUNT=0
	d={}
	d['packet']=ALL_SEND_PACKET
	d['link']=ALL_LINK
	while True:
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
			BNP_COUNT=line.split()[1]
		if "ALL_TARGET" in line:
			ALL_TARGET=line.split()[1]			
	# mid_count=len(node_set)-reply_count

	print "fastrace"
	print "dst sum",ALL_TARGET
	if ALL_SEND_PACKET == 0:
		return d
	print "ALL_SEND_PACKET",ALL_SEND_PACKET
	print "BNP_REDUNDANCE_COUNT",BNP_REDUNDANCE_COUNT
	print "rebundary rate:",BNP_REDUNDANCE_COUNT*1.0/ALL_SEND_PACKET
	print "ALL_NODE,ALL_LINK",ALL_NODE,ALL_LINK
	print "BNP_COUNT",BNP_COUNT
	# print BNP_REDUNDANCE_COUNT/ALL_SEND_PACKET

	d['packet']=ALL_SEND_PACKET
	d['link']=ALL_LINK
	return d
def get_scamper_packet_by_file(sfile):
	hops={}
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
	print "scamper"
	print "dst sum",len(dst_set)
	print "all link",len(link_set),"all node",len(node_set),"all_packet",all_packet
	print "all time",all_time
	if all_time!=0:
		print "avg send packet",1.0*all_packet/all_time
	d={}
	d['packet']=all_packet
	d['link']=len(link_set)
	return d
def every_packet_rate(ffile,sfile):
	fr=ftrace=get_fastrace_packet_by_file(ffile)
	sr=strace=get_scamper_packet_by_file(sfile)
	if sr['link']!=0 and sr['packet']!=0:
		print "link rate",fr['link']*1.0/sr['link']
		print "packet rate",fr['packet']*1.0/sr['packet']

def cmp_packet_rate150():
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
			print dirpath
			ffile=dirpath+dirname+"/test-fastrace2.fastrace"
			if os.path.exists(ffile):
				# print sfile
				sfile=sroot+dirname+"/test-fastrace-scamper.json"
				if os.path.exists(sfile):
					print "----------------------"
					print sfile
					print dirpath+dirname
					every_packet_rate(ffile,sfile)
			else:
				pass
				print "ftrace data no exist",dirname
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
		cmp_packet_rate150()
