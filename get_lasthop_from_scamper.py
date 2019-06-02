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
	all_ip=0
	last_hop_count=1
	# for file in list_dir:
	if True:
		fr=open(sys.argv[1],'r')
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
					if len_hops<=1:
						continue
					if (int)(hops[len_hops-2]['probe_ttl']) +1  == int(hops[len_hops-1]['probe_ttl']) and jo['dst'] == hops[len_hops-1]['addr']:
						last_hop_count+=1
						fw.write(jo['dst']+" "+hops[len_hops-2]['addr'])
		fr.close()

	fw.close()
	print "last_hop_count:",last_hop_count
		# print i,item

if __name__ == '__main__':
	get_link_node_from_dir()
