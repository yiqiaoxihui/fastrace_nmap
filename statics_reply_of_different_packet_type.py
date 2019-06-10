
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

def get_fastrace_mix(ffile):
	global icmp,tcp,udp,mix,isum,tsum,usum,mmix
	all_ip=0
	frf=open(ffile,'r')
	while True:
		line=frf.readline()
		if not line:
			break
		if "TARGET_ARRIVE" in line:
			if int(line.split()[1])>100:
				mix+=int(line.split()[1])
				mmix+=4096
	frf.close()
def get_fastrace_tcp(ffile):
	global icmp,tcp,udp,mix,isum,tsum,usum,mmix,isum,tsum,usum,mmix
	all_ip=0
	frf=open(ffile,'r')
	while True:
		line=frf.readline()
		if not line:
			break
		if "TARGET_ARRIVE" in line:
			if int(line.split()[1])>100:
				tcp+=int(line.split()[1])
				tsum+=4096
	frf.close()
def get_fastrace_icmp(ffile):
	global icmp,tcp,udp,mix,isum,tsum,usum,mmix
	all_ip=0
	frf=open(ffile,'r')
	while True:
		line=frf.readline()
		if not line:
			break
		if "TARGET_ARRIVE" in line:
			if int(line.split()[1])>100:
				icmp+=int(line.split()[1])
				isum+=4096
	frf.close()
def get_fastrace_udp(ffile):
	global icmp,tcp,udp,mix,isum,tsum,usum,mmix
	all_ip=0
	frf=open(ffile,'r')
	while True:
		line=frf.readline()
		if not line:
			break
		if "TARGET_ARRIVE" in line:
			if int(line.split()[1])>100:
				udp+=int(line.split()[1])
				usum+=4096
	frf.close()
def cmp_correct150():
	global icmp,tcp,udp,mix,isum,tsum,usum,mmix
	froot=sys.argv[1]
	max_hop_gap={}
	for dirpath, dirnames, filenames in os.walk(froot):
		# for filepath in filenames:
		#     print os.path.join(dirpath, filepath)
		for dirname in dirnames:
			# print dirname
			# print dirpath
			mfile="test-fastrace6/"+dirname+"/test-fastrace6.fastrace"
			tfile=dirpath+dirname+"/test-fastrace3.TCP.fastrace"
			ifile=dirpath+dirname+"/test-fastrace3.ICMP.fastrace"
			ufile=dirpath+dirname+"/test-fastrace3.UDP.fastrace"
			print mfile
			print tfile
			if os.path.exists(mfile) and os.path.exists(tfile) and os.path.exists(ifile) and os.path.exists(ufile):
				get_fastrace_mix(mfile)
				get_fastrace_icmp(ifile)
				get_fastrace_udp(ufile)
				get_fastrace_tcp(tfile)
			else:
				pass
				print dirname
	print "icmp,tcp,udp,mix"
	print icmp,tcp,udp,mix
	print "isum,tsum,usum,mmix"
	print isum,tsum,usum,mmix
	print icmp*1.0/isum,tcp*1.0/tsum,udp*1.0/usum,mix*1.0/mmix
if __name__ == '__main__':
	global icmp,tcp,udp,mix,isum,tsum,usum,mmix
	icmp=0
	tcp=0
	udp=0
	mix=0
	isum=0
	tsum=0
	usum=0
	mmix=0
	# get_fastrace()
	# get_scamper()
	# cmp_correct()
	# get_all_scamper()
	# mutil_cmp_correct()
	# more_cmp_correct()
	# sc_warts2json()
	cmp_correct150()
	# sc_warts2text()

