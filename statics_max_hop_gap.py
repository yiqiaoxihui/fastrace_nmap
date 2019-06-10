
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
def sc_warts2json():
	for dirpath, dirnames, filenames in os.walk(sys.argv[1]):
		# for filepath in filenames:
		#     print os.path.join(dirpath, filepath)
		for dirname in dirnames:
			sfile=sys.argv[1]+dirname+"/test-fastrace-scamper.warts"
			sjson=sys.argv[1]+dirname+"/test-fastrace-scamper.json"
			print sfile
			if os.path.exists(sfile):
				if os.path.exists(sjson):	#
					print sfile+" has json"
					continue
				else:
					cmd="sc_warts2json "+sfile+" > "+sjson
					print cmd
					err=os.system(cmd)
					print sjson+" "+str(err)
def sc_warts2text():
	for dirpath, dirnames, filenames in os.walk(sys.argv[1]):
		# for filepath in filenames:
		#     print os.path.join(dirpath, filepath)
		for dirname in dirnames:
			sfile=sys.argv[1]+dirname+"/test-fastrace-scamper.warts"
			stext=sys.argv[1]+dirname+"/test-fastrace-scamper.text"
			print sfile
			if os.path.exists(sfile):
				if os.path.exists(stext):	#
					print sfile+" has text"
					continue
				else:
					cmd="sc_warts2text "+sfile+" > "+stext
					print cmd
					err=os.system(cmd)
					print stext+" "+str(err)
def get_fastrace_gap(ffile):
	all_ip=0
	frf=open(ffile,'r')
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
			ftrace[dst]['maxhop']=0
			line=frf.readline()
			i=1 			#ttl from 1 for fastrace
			# print "Target",dst
			while line[0]=="~":
				# print i,line.split()[2]
				if line.split()[2] != "0":
					ftrace[dst]['hop'][i]=line.split()[2]
					ftrace[dst]['maxhop']=i
				line=frf.readline()
				i+=1
				if not line:
					break
			while "Target" not in line:
				line=frf.readline()
				if not line:
					break
		else:
			line=frf.readline()
		if not line:
			break
	frf.close()
	print "fastrace ",all_ip
	return ftrace
def get_scamper(sfile):
	all_ip=0
	frs=open(sfile,'r')
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
			strace[dst]['maxhop']=0
			strace[dst]['hop']={}
			if jo.has_key('hops'):
				hops=jo['hops']
				for hop in hops:
					strace[dst]['hop'][int(hop['probe_ttl'])]=hop['addr']
					strace[dst]['maxhop']=int(hop['probe_ttl'])
					# print hop['probe_ttl'],hop['addr']	
	frs.close()
	print "scamper",all_ip
	return strace
def cmp_correct150():
	sroot=sys.argv[2]
	froot=sys.argv[1]
	max_hop_gap={}
	for dirpath, dirnames, filenames in os.walk(froot):
		# for filepath in filenames:
		#     print os.path.join(dirpath, filepath)
		for dirname in dirnames:
			# print dirname
			# print dirpath
			ffile=dirpath+dirname+"/test-fastrace2.fastrace"
			if os.path.exists(ffile):
				# print sfile
				sfile=sroot+dirname+"/test-fastrace-scamper.json"
				if os.path.exists(sfile):
					print sfile
					print "----------------------"
					print dirpath+dirname
					# get_every_gap(ffile,sfile)
					strace=get_fastrace_gap(ffile)
					strace=get_scamper_gap(sfile)
					for dst in ftrace:
						if strace.has_key(dst) and ftrace.has_key(dst)==True:
							if strace[dst]['maxhop']==0 or ftrace[dst]['maxhop'] ==0
							gap=strace[dst]['maxhop']-ftrace[dst]['maxhop']
							if gap>5:
								print sfile,dst,strace[dst]['maxhop'],ftrace[dst]['maxhop']
							if max_hop_gap.has_key(gap):
								max_hop_gap[gap]+=1
							else:
								max_hop_gap[gap]=0
			else:
				pass
				print dirname
	x=[]
	y=[]
	for i in range(-10,10):
		x.append(i)
		if max_hop_gap.has_key(i):
			y.append(max_hop_gap[i])
		else:
			y.append(0)
	draw_gap(x,y)
def draw_gap(x1,y1):
	#plt.plot(x1,y1,label='router')#,linewidth=3,color='r',marker='o', markerfacecolor='blue',markersize=12 
	plt.plot(x1,y1,label='') 

	# plt.yticks(range(0,100,10))
	plt.xlabel('')
	plt.ylabel('')
	plt.title('')
	plt.legend() 
	# plt.gca().yaxis.set_major_formatter(FuncFormatter(to_percent))
	plt.show() 
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
	# more_cmp_correct()
	# sc_warts2json()
	# cmp_correct150()
	# sc_warts2text()

