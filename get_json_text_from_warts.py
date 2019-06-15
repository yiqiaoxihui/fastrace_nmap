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
def sc_warts2json():
	for dirpath, dirnames, filenames in os.walk(sys.argv[1]):
		# for filepath in filenames:
		#     print os.path.join(dirpath, filepath)
		for dirname in dirnames:
			sfile=sys.argv[1]+dirname+"/test-fastrace-scamper"+sys.argv[2]+".udp.warts"
			sjson=sys.argv[1]+dirname+"/test-fastrace-scamper"+sys.argv[2]+".udp.json"
			print sfile
			if os.path.exists(sfile):
				if os.path.exists(sjson):	#
					print sfile+" has json"
					continue
				else:
					cmd="sc_warts2json "+sfile+" > "+sjson
					print cmd
					err=os.system(cmd)
					print sjson+" "+str(err)
def sc_warts2text():
	for dirpath, dirnames, filenames in os.walk(sys.argv[1]):
		# for filepath in filenames:
		#     print os.path.join(dirpath, filepath)
		for dirname in dirnames:
			sfile=sys.argv[1]+dirname+"/test-fastrace-scamper"+sys.argv[2]+".udp.warts"
			stext=sys.argv[1]+dirname+"/test-fastrace-scamper"+sys.argv[2]+".udp.text"
			print sfile
			if os.path.exists(sfile):
				if os.path.exists(stext):	#
					print sfile+" has text"
					continue
				else:
					cmd="sc_warts2text "+sfile+" > "+stext
					print cmd
					err=os.system(cmd)
					print stext+" "+str(err)
sc_warts2text()
sc_warts2json()
