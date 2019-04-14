local bin = require "bin"
local coroutine = require "coroutine"
local dhcp = require "dhcp"
local ipOps = require "ipOps"
local math = require "math"
local nmap = require "nmap"
local packet = require "packet"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local dns = require "dns"
-- package.path = package.path..";/home/ly/fastrace_nmap/?.lua"
require('base')
description = [[
	send udp packet with big port to get network distance(ttl) from source to target.
	using the ttl to get last hop of the traget.
]]

---
-- @usage
-- sudo nmap --script last_hop --script-args='ip_file=ip.filename.path'
-- 
-- @output
-- | get last hop: 
-- |   network distance: ttl value
-- |_  last hop : ip address 
--
--

-- Version 0.01
-- Created 09/25/2018 - v0.01 - created by Liu Yang

author = "Liu Yang"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}
-- The Head Section --

-- prerule=function()
-- 	return true
-- end
-- The Rule Section --
prerule=function()
	return true
end
-- The Rule Section --
hostrule=function(host)
	--print("hostrule()")
	return true
end
-- local	PROBING_DPORT_ARRAY={
-- 	    80, 45981, 0,
-- 	    80, 80, 80,
-- 	    45981, 47091, 49077,
-- 	    0, 0, 0,
-- 	    21, 53, 109,
-- 	    0, 25, 443
-- 	}
local function send_icmp_echo(pi)
	echo_seq=math.random(0x0, 0xffff)
	echo_id=math.random(0x0, 0xffff)
	-- echo_seq=1
	local str_hex_ip=ipOps.todword(pi['dst'])
	print(echo_seq,echo_id)
	local icmp_tole_rec_socket=nmap.new_socket()
	-- local str_echo_seq=packet.numtostr16(echo_seq)
	local capture_rule_echo_reply="(icmp[0]="..ICMP_ECHOREPLY.." and icmp[1]="..ICMP_ECHOREPLY_CODE.." and icmp[4:2]="..echo_id.." and icmp[6:2]="..echo_seq..")"
	local capture_rule_icmp_error="(icmp[0]="..ICMP_TIME_EXCEEDED.." and icmp[1]="..ICMP_EXC_TTL.." and icmp[34:2]="..echo_seq.." and icmp[32:2]="..echo_id..")"--(icmp[0]=11) and (icmp[1]=0) and 
	local capture_rule_icmp=capture_rule_echo_reply.." or "..capture_rule_icmp_error
	print(capture_rule_icmp)
	-- local capture_rule="(icmp[0]=11) and (icmp[1]=0) and icmp[24:4]="..str_hex_ip
	icmp_tole_rec_socket:pcap_open(iface.device,128,false,capture_rule_icmp)
	icmp_tole_rec_socket:set_timeout(pi['wt'])

	ip=packet.Packet:new()
	ip.ip_bin_dst=ipOps.ip_to_str(pi['dst'])
	ip.ip_bin_src = ipOps.ip_to_str(iface.address)
	-- ip.ip_p=6
	ip.echo_data = "abc"
	-- ip.icmp_payload="asfg"
	-- ip.icmp_type=1
	-- ip.icmp_code=1
	ip.echo_seq = echo_seq
	ip.echo_id=echo_id
	ip.ip_offset=0
	ip:build_icmp_echo_request()
	ip:build_icmp_header()
	ip:build_ip_packet()
	ip:ip_set_ttl(pi['ttl'])
	-- for k,v in pairs(ip) do
	-- 	print("ip:",k,v)
	-- end
	send_l3_sock:ip_send(ip.buf)
	local status,len,l2_icmp_t_l,l3_icmp_tole,time=icmp_tole_rec_socket:pcap_receive()
	if status then
		print("get icmp exceed back,len:",len)
		local icmp_timeexc_packet = packet.Packet:new(l3_icmp_tole, #l3_icmp_tole)
		from=icmp_timeexc_packet['ip_src']
		for k,v in pairs(icmp_timeexc_packet) do
			print("ip:",k,v)
		end
		print(">HOP:",pi['ttl'],from)

	else
		print("!HOP:",pi['ttl'],"timeout")
	end
end
local function fail(err) return ("\n  ERROR: %s"):format(err or "") end
local function hopping(dst_ip,ttl,try)
	local pi={}		--探测信息
	local send_packet_type=PROBING_TYPE_ARRAY[try]
	pi['dport']=PROBING_DPORT_ARRAY[try]
	pi['wt']=3000								--wait time
	pi['ttl']=ttl
	pi['dst']=dst_ip
	local return_packet_type
	local from
	if send_packet_type==PPK_ICMPECHO then		--3
		print("send icmp echo packet")
		return_packet_type, from=send_icmp_echo(pi)
	elseif send_packet_type==PPK_ACK then

	elseif send_packet_type==PPK_SYN then

	elseif send_packet_type==PPK_FIN then

	elseif send_packet_type==PPK_UDPBIGPORT then
	end
	-- body
end
local function send_udp_big_port(pi,send_l3_sock,device)
	
end

action=function(host)
	local ifname = nmap.get_interface() or host.interface
	if not ifname then
		return fail("Failed to determine the network interface name")
	end
	iface = nmap.get_interface_info(ifname)
	send_l3_sock = nmap.new_dnet()
	send_l3_sock:ip_open()
	local dst_ip=stdnse.get_script_args("ip")
	if not dst_ip then
		return fail("no target in input")
	end
	--针对单个ip的正常traceroute
	-- normal_traceroute(dst_ip)
	hopping('47.90.99.168',6,3)
end