import os
import sys
import shlex
import subprocess
import time
print "script_path,outfilename,iface,ip"
file_path=sys.argv[2]
script_path=sys.argv[1]
ip=sys.argv[4]
iface=sys.argv[3]
print script_path, file_path
packet_type_dic={}
packet_type_dic[1]='TCP'
packet_type_dic[2]='UDP'
packet_type_dic[3]='ICMP'
packet_type_dic[4]='MIX'

for key in packet_type_dic:
	print packet_type_dic[key]
	time.sleep(3)
	fw=open("fi36.56.0.0_13.min26.verbose."+packet_type_dic[key],"w")
	script_args="'max_timeout_per_hop=3,packet_type="+packet_type_dic[key]+",verbose=1,ip=36.56.0.0/20,output_type=file,output_filename=fi36.56.0.0_13.min26."+packet_type_dic[key]+",improve=1'"
	cmd="nmap -e "+iface+" --script "+script_path+" --script-args="+script_args
	print cmd
	fw.write(cmd)
	cmd = shlex.split(cmd)
	p = subprocess.Popen(cmd, shell=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
	difference={}
	set_ttl_and_send=0
	while p.poll() is None:
		line = p.stdout.readline().strip()
		fw.write(line)
		print line
	fw.close()
	if p.returncode == 0:
		print('Subprogram success')
	else:
		print('Subprogram failed')
		break