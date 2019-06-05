from netaddr import IPNetwork
import sys

fw=open(sys.argv[2],'w')
if sys.argv[3]=='1':
	ip=IPNetwork(sys.argv[1])
	for i in ip:
		print i
		fw.write(str(i)+"\n")
else:
	with open(sys.argv[1], 'r') as cidrRanges:
		for line in cidrRanges:
			ip = IPNetwork(line)
			for i in ip:
				fw.write(str(i)+"\n")
fw.close()
