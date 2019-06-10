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

if __name__ == '__main__':
	get_link_node_from_dir()
