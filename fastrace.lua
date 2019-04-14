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
require('prober')
-- require('parsepack') in prober

description = [[
	a traceroute tool,design some new way to improve traceroute
]]

---
-- @usage
-- sudo nmap --script fastrace --script-args='ip=52.78.22.146'
-- 
-- @output
-- 
--

-- Version 0.01
-- Created 04/11/2019 - v0.01 - created by Liu Yang

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

local function GET_TRY(try)
	if try >= NR_PROBING_ARRAY then
		try = 1
	else
		try=try+1
	end
	return try
end


local function hopping(dst_ip,ttl,try)
	local pi={}		--探测信息
	-- print(try)
	local send_packet_type=PROBING_TYPE_ARRAY[try]
	pi['dport']=PROBING_DPORT_ARRAY[try]
	pi['sport']=math.random(0x7000, 0xffff)		--why from 7000
	pi['wt']=3000								--wait time
	pi['ttl']=ttl
	pi['dst']=dst_ip
	pi['src']=iface.address
	local rpk_type=0
	local from
	if send_packet_type==PPK_ICMPECHO then		--3
		-- print("probe type:PPK_ICMPECHO")
		rpk_type, from=prober.send_icmp_echo(pi,send_l3_sock,iface.device)
	elseif send_packet_type==PPK_ACK then

	elseif send_packet_type==PPK_SYN then
		-- print("probe type:PPK_TCP_SYN")
		rpk_type, from=prober.send_tcp_syn(pi,send_l3_sock,iface.device)
	elseif send_packet_type==PPK_FIN then

	elseif send_packet_type==PPK_UDPBIGPORT then
		-- print("probe type:PPK_UDPBIGPORT")
		rpk_type, from=prober.send_udp_big_port(pi,send_l3_sock,iface.device)
		-- print("probe result:rpk_type,from:",rpk_type,from)
	end
	return rpk_type,from
	-- body
end
local function forward_traceroute(trace,cmptrace)
	local ttl			
	local rpk_type				--返回包类型
	local from					--探测回复的源ip
	local timeout=0				--一跳上的探测超时计数器
	local timeout_hops=0		--hop超时计数器，意思是连续有timeout_hops跳未响应，即退出
	local compare_each_from=0	--
	local timeouth=0
	try=1					--更改发包类型,lua，table下标从0开始
	if cmptrace then
		if trace['start']==0 then
			trace['start']=cmptrace['end']
			compare_each_from=0
		else
			compare_each_from=1
		end
	end
	ttl=trace['start']
	trace['hop']={}
	print("forward_traceroute:")
	while ttl <= MAX_HOP do
		-- print("begin:",timeout,timeout_hops)
		::hopping_begin::
		if timeout >=1 or timeout_hops>=1 then
			--try=GET_TRY(try)
		end
		-- print("begin hopping:",rpk_type,from)
		rpk_type,from=hopping(trace['dst'],ttl,try)
		-- print("hopping:",rpk_type,from)
		if rpk_type==0 then
			print("forward_traceroute stop because rpk_type 0!")
			return -1
		end
		-- if rpk_type==RPK_TIMEEXC then
			
		-- 	trace['hop'][ttl]=from
		-- 	ttl=ttl+1
		-- end
		--超时未响应
		if rpk_type==RPK_TIMEOUT then
			timeout=timeout+1
			print("*HOP:",ttl,"timeout:",timeout,timeout_hops)
			if compare_each_from==1 and cmptrace ~=nil then
				--TODO:近邻无应答结束技术 NNS
			end
			if timeout==MAX_TIMEOUT_PER_HOP then	--连续3次超时
				timeout=0
				timeout_hops=timeout_hops+1
				trace['hop'][ttl]=0
				if timeout_hops>=MAX_TIMEOUT_HOPS then	--1
					--Too many continuous timeout.
					--Remain a router ZERO at the end of path.
					trace['end']=ttl - MAX_TIMEOUT_HOPS+1
					trace['rst']=TR_RESULT_TIMEOUT
					if timeouth>=1 then
						print("TOH OK")
					end
					print("!TR_RESULT_TIMEOUT:",ttl,"timeout:",timeout,timeout_hops)
					return 1
				end		--end timeout_hops==MAX_TIMEOUT_HOPS
				ttl=ttl+1
			end	--end timeout==MAX_TIMEOUT_PER_HOP
			goto hopping_begin
		end		--end rpk_type==RPK_TIMEOUT 
		--收到回复包，重置超时计数器
		timeout = 0
		timeout_hops = 0
		--/* Record response IP address. */
		trace['hop'][ttl]=from
		if rpk_type == RPK_TIMEEXC then
			if ttl>2 and from ~= trace['hop'][ttl-2] then
				local i
				for i=trace['start'],ttl-2 do 		--从start到ttl-2 与from对比，查看是否一致
					if from==trace['hop'][i] then	--
						trace['end']=ttl
						trace['rst']=TR_RESULT_LOOP
						print("TR_RESULT_LOOP:",ttl,"get target:",from)
						return 1
					end
				end
			end		--end if ttl>2 and from ~= trace['hop'][ttl-2]
			if from == trace['dst'] then		--生存时间超时，却是目标发送的
				print("!TR_RESULT_FAKE:",ttl,"get target:",from)
				trace['end']=ttl
				trace['rst']=TR_RESULT_FAKE
				return 1
			end		--end if from == trace['dst']
			if cmptrace ~= nil then
				--TODO:treetrace
			end
			print(">HOP:",ttl,"from:",from)
			ttl=ttl+1
			--goto begin
			goto hopping_begin
		end		--end rpk_type== RPK_TIMEEXC
		if (IS_UNREACH(rpk_type)==1) then
			local code = rpk_type  - RPK_UNREACH
			--不是端口不可达和协议不可达的，都停止探测，why 协议不可达也可以继续
			if code ~=  ICMP_PROT_UNREACH  and  code ~= ICMP_PORT_UNREACH then
				trace['end'] = ttl
				trace['rst'] = TR_RESULT_UNREACH
				return 1
			end
		end	--end if(is_unreach(rpk_type))
		--排除超时未响应，ICMP生存时间超时，ICMP目标不可达(除去端口不可达、协议不可达)，返回包类型可能为：
		--1.ICMP echo reply,端口不可达，协议不可达
		--2.TCP RPK_RST	,RPK_SYNACK	,RPK_RSTACK
		trace['end']=ttl
		trace['rst']=TR_RESULT_GOTTHERE
		print(">HOP:",ttl,"get target:",from)
		return 1
		-- if rpk_type==RPK_ICMPECHO then
		-- 	print(">HOP:",ttl,"get target:",from)
		-- 	trace_flag=1
		-- end
	end
	trace['end']=MAX_HOP
	trace['rst']=TR_RESULT_MAXHOP
	return 1
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
	-- rpk_type,from= hopping(dst_ip,32,1)
	-- print(rpk_type,from)
	normal_traceroute(dst_ip)
	return true
end