
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

def get_scamper(sfile):
	ALL_TARGET=0
	TARGET_ARRIVE=0
	fr=open(sfile,'r')
	# print file
	while True:
		line = fr.readline().strip()
		if not line:
			break
		else:
			jo=json.loads(line)
			if jo.has_key('dst')==False:
				continue
			ALL_TARGET+=1
			dst=jo['dst']
			if jo.has_key('hops'):
				hops=jo['hops']
				len_hops=len(hops)
				if len_hops<=0:
					continue
				if hops[len_hops-1]['addr'] ==dst:
					TARGET_ARRIVE+=1
	fr.close()
	return ALL_TARGET,TARGET_ARRIVE
def get_fastrace(ffile):
	global icmp,tcp,udp,mix,isum,tsum,usum,msum
	ALL_TARGET=0
	TARGET_ARRIVE=0
	frf=open(ffile,'r')
	while True:
		line=frf.readline()
		if not line:
			break
		if "TARGET_ARRIVE" in line:
			TARGET_ARRIVE=int(line.split()[1])
		if "ALL_TARGET" in line:
			ALL_TARGET=int(line.split()[1])
	frf.close()
	return ALL_TARGET,TARGET_ARRIVE
def cmp_correct150():
	global icmp,tcp,udp,mix,isum,tsum,usum,msum
	froot=sys.argv[1]
	max_hop_gap={}
	index=1
	for dirpath, dirnames, filenames in os.walk(froot):
		# for filepath in filenames:
		#     print os.path.join(dirpath, filepath)
		for dirname in dirnames:
			# print dirname
			# print dirpath
			mfile="test-fastrace4/"+dirname+"/test-fastrace4.fastrace"
			tfile=dirpath+dirname+"/test-fastrace3.TCP.fastrace"
			ifile=dirpath+dirname+"/test-fastrace3.ICMP.fastrace"
			ifile="test-fastrace-scamper/"+dirname+"/test-fastrace-scamper.json"
			ufile=dirpath+dirname+"/test-fastrace3.UDP.fastrace"
			if os.path.exists(mfile) and os.path.exists(tfile) and os.path.exists(ifile) and os.path.exists(ufile):
				mix_t,mix_a=get_fastrace(mfile)
				# icmp_t,icmp_a=get_fastrace(ifile)
				icmp_t,icmp_a=get_scamper(ifile)
				udp_t,udp_a=get_fastrace(ufile)
				tcp_t,tcp_a=get_fastrace(tfile)
				
				if mix_t==4096 and icmp_t==4096 and udp_t==4096 and tcp_t==4096:
					if mix_a!=0 and icmp_a!=0 and udp_a!=0 and tcp_a!=0:
						print '--------------------'
						print index
						index+=1
						print mfile
						print tfile
						print "mix",mix_t,mix_a,mix_a*1.0/mix_t
						print "icmp",icmp_t,icmp_a,icmp_a*1.0/icmp_t
						print "tcp",tcp_t,tcp_a,tcp_a*1.0/tcp_t
						print "udp",udp_t,udp_a,udp_a*1.0/udp_t
						mix+=mix_a
						icmp+=icmp_a
						tcp+=tcp_a
						udp+=udp_a

						msum+=mix_t
						isum+=icmp_t
						tsum+=tcp_t
						usum+=udp_t
			else:
				pass
				# print "skip",dirname
	print "icmp,tcp,udp,mix"
	print icmp,tcp,udp,mix
	print "isum,tsum,usum,msum"
	print isum,tsum,usum,msum
	print icmp*1.0/isum,tcp*1.0/tsum,udp*1.0/usum,mix*1.0/msum
if __name__ == '__main__':
	global icmp,tcp,udp,mix,isum,tsum,usum,msum
	icmp=0
	tcp=0
	udp=0
	mix=0
	isum=0
	tsum=0
	usum=0
	msum=0
	# get_fastrace()
	# get_scamper()
	# cmp_correct()
	# get_all_scamper()
	# mutil_cmp_correct()
	# more_cmp_correct()
	# sc_warts2json()
	cmp_correct150()
	# sc_warts2text()

