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
def get_link_node_from_dir(file):
	all_ip=0
	host_distribution={}
	host=set()
	router=set()
	router_distribution={}
	hops={}
	host_ip=0
	# list_dir = os.listdir(file_dir)
	all_link=set()
	all_node=set()
	all_packet=0
	all_time=0
	# for file in list_dir:
	if True:

		#print file
		if file[-5:]==".json":
			fr=open(file,'r')
			print file
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
					if jo.has_key('probe_count'):
						all_packet+=int(jo['probe_count'])
					dst=jo['dst']
					host.add(dst)
					if jo.has_key('hops'):
						hops=jo['hops']
						len_hops=len(hops)
						if len_hops<=0:
							continue
						for i in range(0,len_hops-1):
							s=hops[i]['addr']
							d=hops[i+1]['addr']
							ip_s=socket.ntohl(struct.unpack("I",socket.inet_aton(s))[0])
							ip_d=socket.ntohl(struct.unpack("I",socket.inet_aton(d))[0])
							if ip_s>ip_d:
								str_ip=d+" "+s
							else:
								str_ip=s+" "+d
							all_link.add(str_ip)
							all_node.add(s)
							all_node.add(d)
			fr.close()
	print "all link",len(all_link),"all node",len(all_node),"all_packet",all_packet
	print "all time",all_time
	print "avg send packet",1.0*all_packet/all_time
	i=0
	for item in all_link:
		i+=1
		# print i,item
	i=0

if __name__ == '__main__':
	get_link_node_from_dir(sys.argv[1])