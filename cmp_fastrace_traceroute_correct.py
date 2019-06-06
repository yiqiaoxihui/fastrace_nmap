
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



def get_fastrace():
	all_ip=0
	frf=open(sys.argv[1],'r')
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
def get_scamper():

	all_ip=0
	frs=open(sys.argv[2],'r')
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
#
def get_all_scamper():
	all_ip=0
	strace={}
	for filename in os.listdir(sys.argv[2]):
		if ".json" == filename[-5:]:
			print "scamper file",filename
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
					if strace.has_key(dst):
						pass
					else:
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
	print "scamper",all_ip
	return strace
def mutil_cmp_correct():
	ftrace=get_fastrace()
	strace=get_all_scamper()
	all_hop=0
	all_same_hop=0
	fastrace_no_hop=0

	for dst in strace:
		trace=strace[dst]
		hops=trace['hop']
		for i in hops:
			#fastrace also has this hop
			if ftrace[dst]['hop'].has_key(i):
				all_hop+=1
				if ftrace[dst]['hop'][i] in hops[i]:
					# print ftrace[dst]['hop'][i] , hops[i]
					all_same_hop+=1
				else:
					print dst,"fastrace not in scamper on ttl",i,ftrace[dst]['hop'][i]
			else:
				fastrace_no_hop+=1
				print dst,"ftrace no this hop",i
	
	print "fastrace no hop count",fastrace_no_hop
	print "all_hop,all_same_hop",all_hop, all_same_hop
	print all_same_hop*1.0/all_hop

def cmp_correct():
	ftrace=get_fastrace()
	strace=get_scamper()
	all_hop=0
	all_same_hop=0
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
					print dst,"fastrace not in scamper on ttl",i,ftrace[dst]['hop'][i]
			else:
				print "ftrace:",len(ftrace[dst]['hop']),'strace:',i
	print "all_hop,all_same_hop",all_hop, all_same_hop
	print all_same_hop*1.0/all_hop

def draw(x1,y1):
	#plt.plot(x1,y1,label='router')#,linewidth=3,color='r',marker='o', markerfacecolor='blue',markersize=12 
	plt.plot(x1,y1,label='') 
	plt.xlabel('') 
	plt.ylabel('') 
	plt.title('') 
	plt.legend() 
	plt.show() 
if __name__ == '__main__':
	# get_fastrace()
	# get_scamper()
	cmp_correct()
	# get_all_scamper()
	# mutil_cmp_correct()
