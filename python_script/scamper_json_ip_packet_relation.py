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
import matplotlib.pyplot as plt 
def get_link_node_from_dir():
	all_ip=0
	host_distribution={}
	host=set()
	router=set()
	router_distribution={}
	hops={}
	host_ip=0
	# list_dir = os.listdir(file_dir)
	link_set=set()
	node_set=set()
	dst_set=set()
	all_packet=0
	all_time=0
	dst_set=set()
	ip_packet_dic={}
	# for file in list_dir:
	if True:
		fr=open(sys.argv[1],'r')
		# while True:
		# 	line = fr.readline().strip()
		# 	if not line:
		# 		break
		# 	jo=json.loads(line)
		# 	if jo.has_key('dst')==False:
		# 		continue
		# 	else:
		# 		dst_set.add(jo['dst'])
		# fr.seek(0,0)
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
				if jo.has_key('hops'):
					hops=jo['hops']
					len_hops=len(hops)
					if len_hops<=0:
						continue
					for i in range(0,len_hops): #target live is new node
						s=hops[i]['addr']
						if IP(s).iptype() != "PRIVATE":
							# if (s in dst_set):
							# 	continue
							# else:
							node_set.add(s)
							ip_packet_dic[len(node_set)]=all_packet
		fr.close()
		x=[]
		y=[]
		fw=open(sys.argv[1]+".ip.packet.relation",'w')
		for i in ip_packet_dic:
			fw.write(str(i)+" "+str(ip_packet_dic[i]))
			print i,ip_packet_dic[i]
			x.append(i)
			y.append(ip_packet_dic[i])
		fw.close()
		print("node:",len(node_set))
# 		draw(x,y)
# def draw(x1,y1):
# 	#plt.plot(x1,y1,label='router')#,linewidth=3,color='r',marker='o', markerfacecolor='blue',markersize=12 
# 	plt.plot(x1,y1,label='') 
# 	plt.xlabel('new node number') 
# 	plt.ylabel('send packets number') 
# 	plt.title('') 
# 	plt.legend() 
# 	plt.show() 
if __name__ == '__main__':
	get_link_node_from_dir()