import os
import sys

f=open(sys.argv[1],'r')
all_ip_number=0
line_number=int(sys.argv[2])
i=0
while True:
	i+=1
	if i>line_number:
		break
	line =f.readline()
	if not line:
		break

	try:
		cidr=line.split('/')[1]
		cidr=int(cidr)
		print "cidr:",cidr
		if cidr<=32:
			all_ip_number+=(1 << (32-cidr))

	except Exception as e:
		print "illege ip",line
print all_ip_number
f.close()