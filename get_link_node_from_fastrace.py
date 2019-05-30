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
def get_node_link():
	fr=open(sys.argv[1],'r')
	pline=""
	line=""
	line=fr.readline()
	link_set=set()
	node_set=set()
	if not line:
		print "file in empty"
		return
	while True:
		pline=line
		line=fr.readline()
		if not line:
			break
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
			link_set.add(str_ip)
			node_set.add(s)
			node_set.add(d)
	for l in link_set:
		print l
	print "all link",len(link_set),"all node",len(node_set)
if __name__ == '__main__':
	get_node_link()