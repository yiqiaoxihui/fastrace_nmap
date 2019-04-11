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
require('base')
description = [[
	a traceroute tool,design some new way to improve traceroute
]]

---
-- @usage
-- sudo nmap --script fastrace --script-args='ip=52.78.22.146'
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

prerule=function()
	return true
end
-- The Rule Section --
hostrule=function(host)
	--print("hostrule()")
	return true
end
local function fail(err) return ("\n  ERROR: %s"):format(err or "") end

local function get_ptype_icmp(l3_icmp_packet,len)
	local icmp_type=l3_icmp_packet['icmp_type']
	local icmp_code=l3_icmp_packet['icmp_code']
	local icmp_payload_offset=l3_icmp_packet['icmp_payload_offset']
	if icmp_type==ICMP_ECHO then
		return PPK_ICMPECHO
	elseif icmp_type==ICMP_ECHOREPLY then
		return RPK_ICMPECHO
	elseif icmp_type==ICMP_DEST_UNREACH then
		if (len-icmp_payload_offset)<(IP_HEAD_SIZE+ICMP_HEAD_SIZE) then
			return 0
		else
			return RPK_UNREACH+icmp_code
		end
	elseif icmp_type==ICMP_TIME_EXCEEDED then
		if (len-icmp_payload_offset)<(IP_HEAD_SIZE+ICMP_HEAD_SIZE) then
			return 0
		else
			return RPK_TIMEEXC
		end
	else
		return 0
	end
end

local function send_icmp_echo(pi)
	local rpk_type
	local from
	echo_seq=math.random(0x0, 0xffff)
	echo_id=math.random(0x0, 0xffff)
	-- echo_seq=1
	local str_hex_ip=ipOps.todword(pi['dst'])
	-- print(echo_seq,echo_id)
	local icmp_tole_rec_socket=nmap.new_socket()
	local capture_rule_echo_reply="(icmp[0]="..ICMP_ECHOREPLY.." and icmp[1]="..ICMP_ECHOREPLY_CODE.." and icmp[4:2]="..echo_id.." and icmp[6:2]="..echo_seq..")"
	--icmp[0]="..ICMP_TIME_EXCEEDED.." and icmp[1]="..ICMP_EXC_TTL.." and 
	local capture_rule_icmp_error="(icmp[34:2]="..echo_seq.." and icmp[32:2]="..echo_id..")"--(icmp[0]=11) and (icmp[1]=0) and 
	local capture_rule_icmp=capture_rule_echo_reply.." or "..capture_rule_icmp_error
	icmp_tole_rec_socket:pcap_open(iface.device,128,false,capture_rule_icmp)
	icmp_tole_rec_socket:set_timeout(pi['wt'])

	ip=packet.Packet:new()
	ip.ip_bin_dst=ipOps.ip_to_str(pi['dst'])
	ip.ip_bin_src = ipOps.ip_to_str(iface.address)
	ip.echo_data = "abc"
	ip.echo_seq = echo_seq
	ip.echo_id=echo_id
	ip.ip_offset=0
	ip:build_icmp_echo_request()
	ip:build_icmp_header()
	ip:build_ip_packet()
	ip:ip_set_ttl(pi['ttl'])
	send_l3_sock:ip_send(ip.buf)
	local status,len,l2_icmp_t_l,l3_icmp_tole,time=icmp_tole_rec_socket:pcap_receive()
	if status then
		-- print("get icmp packet back")
		local icmp_rpk_packet = packet.Packet:new(l3_icmp_tole, #l3_icmp_tole)
		from=icmp_rpk_packet['ip_src']
		-- for k,v in pairs(icmp_timeexc_packet) do
		-- 	print("ip:",k,v)
		-- end
		rpk_type=get_ptype_icmp(icmp_rpk_packet,len)
		-- print(">HOP:",pi['ttl'],from)

	else
		print("!HOP:",pi['ttl'],"timeout")
		rpk_type=RPK_TIMEOUT

	end
	return rpk_type,from
end
local function hopping(dst_ip,ttl,try)
	local pi={}		--探测信息
	local send_packet_type=PROBING_TYPE_ARRAY[try]
	pi['dport']=PROBING_DPORT_ARRAY[try]
	pi['wt']=3000								--wait time
	pi['ttl']=ttl
	pi['dst']=dst_ip
	local rpk_type=0
	local from
	if send_packet_type==PPK_ICMPECHO then		--3
		rpk_type, from=send_icmp_echo(pi)
	elseif send_packet_type==PPK_ACK then

	elseif send_packet_type==PPK_SYN then

	elseif send_packet_type==PPK_FIN then

	elseif send_packet_type==PPK_UDPBIGPORT then
	end
	return rpk_type,from
	-- body
end
local function forward_traceroute(trace,cmptrace)
	local ttl			
	local rpk_type				--返回包类型
	local from					--探测回复的源ip
	local timeout=0				--一跳上的探测超时计数器
	local timeout_hops=0		--hop超时计数器
	local compare_each_from=0	--
	local timeouth=0
	local try=3					--更改发包类型,lua，table下标从0开始
	if cmptrace then
		if trace['start']==0 then
			trace['start']=cmptrace['end']
			compare_each_from=0
		else
			compare_each_from=1
		end
	end
	ttl=trace['start']
	local trace_flag=0
	print("forward_traceroute:")
	repeat
		-- print("begin hopping:",rpk_type,from)
		rpk_type,from=hopping(trace['dst'],ttl,try)
		-- print("hopping:",rpk_type,from)
		if rpk_type==0 then
			trace_flag=1
		end
		if rpk_type==RPK_TIMEEXC then
			print(">HOP:",ttl,"from:",from)
			trace[ttl]=from
			ttl=ttl+1
		end
		if rpk_type==RPK_TIMEOUT then
			ttl=ttl+1
		end
		if rpk_type==RPK_ICMPECHO then
			print(">HOP:",ttl,"get target:",from)
			trace_flag=1
		end
	until ttl>32 or trace_flag==1
end

local function normal_traceroute(dst_ip)
	local trace={}
	trace['dst']=dst_ip
	trace['start']=1
	forward_traceroute(trace,nil)
end

action=function()
	print("__________________")
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
	normal_traceroute(dst_ip)
	return true
end