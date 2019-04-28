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
require('last_hop')
require('unit_test')
local Stack=require('stack')
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
		print("probe type:PPK_ICMPECHO")
		rpk_type, from=prober.send_icmp_echo(pi,send_l3_sock,iface.device)
	elseif send_packet_type==PPK_ACK then
		print("probe type:PPK_TCP_ACK")	--效果不佳
		rpk_type, from=prober.send_tcp_ack(pi,send_l3_sock,iface.device)
	elseif send_packet_type==PPK_SYN then
		print("probe type:PPK_TCP_SYN")
		rpk_type, from=prober.send_tcp_syn(pi,send_l3_sock,iface.device)
	elseif send_packet_type==PPK_FIN then
		print("probe type:PPK_TCP_FIN")	--效果很差
		rpk_type, from=prober.send_tcp_fin(pi,send_l3_sock,iface.device)
	elseif send_packet_type==PPK_UDPBIGPORT then
		print("probe type:PPK_UDPBIGPORT")
		rpk_type, from=prober.send_udp_big_port(pi,send_l3_sock,iface.device)
		-- print("probe result:rpk_type,from:",rpk_type,from)
	end
	return rpk_type,from
	-- body
end

--/* Reverse version of forward_traceroute(), not TTL++ but TTL--. 
-- * TTL start from `trace'->end, and destination host is `trace'->dst.
-- * Traceroute finished until TTL == 1 or found the same router as `cmptrace'
-- * on the same hop.
-- */
--//BNP backward on neighbor’s path
local function reverse_traceroute(trace,cmptrace)
	local ttl			
	local rpk_type				--返回包类型
	local code					--ICMP错误代码
	local from					--探测回复的源ip
	local timeout=0				--探测超时计数器
	try =3
	trace['rst']=0
	if trace['end'] > MAX_HOP then
		trace['end'] = MAX_HOP
	end
	ttl=trace['end']
	while ttl ~=0 do
		rpk_type,from=hopping(trace['dst'],ttl,try)
		if rpk_type ==0 then
			return -1
		end
		if rpk_type == RPK_TIMEOUT then
			print("*HOP:",ttl,"timeout:",timeout)
			trace['hop'][ttl]=0
			-- ttl=ttl-1
			goto reverse_hopping_begin
		end
		timeout=0
		trace['hop'][ttl] = from
		if rpk_type ~= RPK_TIMEEXC then
			if IS_UNREACH(rpk_type) then
				code=rpk_type - RPK_UNREACH
				if code ~= ICMP_PROT_UNREACH and code ~= ICMP_PORT_UNREACH then
					trace['rst'] = TR_RESULT_UNREACH
				else
					print(">HOP:",ttl,"get target:",from)
					trace['rst'] = TR_RESULT_GOTTHERE
				end
			else
				print(">HOP:",ttl,"get target:",from)
				trace['rst'] = TR_RESULT_GOTTHERE
			end
            --/* If `ttl' isn't equal to `trace->end', it means:
            -- * When we had found some routers on farther hops, we got a 
            -- * finished return packet. This may be caused by a too large 
            -- * end TTL value or Amazing! We change end TTL value
            -- */
            trace['end']=ttl;
            -- ttl=ttl-1
            goto reverse_hopping_begin
        end
        print(">HOP:",ttl,"from:",from)
        --错误的报文
        if from == trace['dst'] then
        	print("!TR_RESULT_FAKE:",ttl,"from:",from)
        	trace['end'] = ttl
        	trace['rst'] = TR_RESULT_FAKE
        	-- ttl=ttl-1
        	goto reverse_hopping_begin
        end
        if cmptrace ~= nil and cmptrace['start'] <= ttl and cmptrace['end'] >= ttl and cmptrace['hop'][ttl] == trace['hop'][ttl] then
        	trace['start'] = ttl
			if trace['rst'] == 0 then		--仅当没有TR_RESULT_GOTTHERE和TR_RESULT_FAKE
				print("TR_RESULT_DESIGN:",ttl,"from:",from)
				trace['rst'] = TR_RESULT_DESIGN
			end
			return 1
		end
		::reverse_hopping_begin::
		ttl=ttl-1
	end
	trace['start']=1
	if trace['rst'] == 0 then
		trace['rst'] = TR_RESULT_DESIGN
	end
	return 1
end
local function forward_traceroute(trace,cmptrace)
	local ttl			
	local rpk_type				--返回包类型
	local code					--ICMP错误代码
	local from					--探测回复的源ip
	local timeout=0				--一跳上的探测超时计数器
	local timeout_hops=0		--hop超时计数器，意思是连续有timeout_hops跳未响应，即退出
	local compare_each_from=0	--
	local timeouth=0
	try=3					--更改发包类型,lua，table下标从0开始
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
		if timeout >=1 or timeout_hops>=1 then
			-- try=GET_TRY(try)
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
					trace['end']=ttl -- - MAX_TIMEOUT_HOPS+1
					trace['rst']=TR_RESULT_TIMEOUT
					if timeouth>=1 then
						print("TOH OK")
					end
					print("!TR_RESULT_TIMEOUT:",ttl,"timeout:",timeout,timeout_hops)
					return 1
				end		--end timeout_hops==MAX_TIMEOUT_HOPS
				ttl=ttl+1
			end	--end timeout==MAX_TIMEOUT_PER_HOP
			-- ttl=ttl+1
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
						print("TR_RESULT_LOOP:",ttl,"from:",from)
						return 1
					end
				end
			end		--end if ttl>2 and from ~= trace['hop'][ttl-2]
			if from == trace['dst'] then		--生存时间超时，却是目标发送的
				print("!TR_RESULT_FAKE:",ttl,"from:",from)
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
			code = rpk_type  - RPK_UNREACH
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
		do
			trace['end']=ttl
			trace['rst']=TR_RESULT_GOTTHERE
			print(">HOP:",ttl,"get target:",from)
			return 1
		end
		-- if rpk_type==RPK_ICMPECHO then
		-- 	print(">HOP:",ttl,"get target:",from)
		-- 	trace_flag=1
		-- end
		::hopping_begin::	--应该放到这里，如果放到while下面，while条件何时判断？可能产生死循环
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
local function treetrace(cidr)
	local newsr = {}
	local oldsr = {}
	local s = Stack:new()
	if cidr['pfx']>=MAX_PREFIX_LEN then
		if (cidr['pfx'] ~=32) and (HOSTADDR(cidr['ip'],cidr['fpx'])==0) then
			cidr['ip']=IP_INC(cidr['ip'])
		end
		normal_traceroute(cidr['ip'])
		return
	end

end

local function last_hop(dst_ip,iface,result)
	local last_hop_condvar = nmap.condvar(result)
	print('target:',dst_ip)
	last_hop_main(dst_ip,iface)
	print('end:',dst_ip)
	last_hop_condvar "signal"
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
	local ip_file=stdnse.get_script_args("ip_file")
	if (not dst_ip)  and (not ip_file) then
		return fail("error:no target input")
	end
	if (dst_ip)  and (ip_file) then
		return fail("error:muti target")
	end

	local prober_type=stdnse.get_script_args("type")	--默认traceroute

	if prober_type =='last_hop' then
		if dst_ip then
			local ip, err = ipOps.expand_ip(dst_ip)
			if not err then
				last_hop_main(dst_ip,iface)
			else
				return fail("error:illege ip")
			end
		elseif ip_file then 		--从文件读入
			local last_hop_thread_handler={}
			local last_hop_result={}
			local last_hop_condvar = nmap.condvar(last_hop_result)
			
			--ip_file="ip10wt"
			local ip_count=0
			local ip_list={}
			for line in io.lines(ip_file) do
				local ip=stdnse.strsplit(" ", line)
				-- print(line,ip[1])
				--print(ip[1])
				--print(line,":send udp packet, port:65534")
				local temp, err = ipOps.expand_ip(ip[1])
				if not err then
					print(ip[1],ip_count)
					ip_count=ip_count+1
					table.insert(ip_list,ip[1])
				else
					print(ip[1],"error:illege ip")
				end
				if #ip_list >= 15 then
					print('begin thread last_hop',ip_count)
					for i in pairs(ip_list) do
						local last_hop_co = stdnse.new_thread(last_hop,ip_list[i],iface,last_hop_result)
						last_hop_thread_handler[last_hop_co]=true
					end
					
				    repeat
				        for thread in pairs(last_hop_thread_handler) do
				            if coroutine.status(thread) == "dead" then
				                last_hop_thread_handler[thread] = nil
				            end
				        end
				        if (next(last_hop_thread_handler)) then
				            last_hop_condvar "wait"
				        end
				    until next(last_hop_thread_handler) == nil
				    ip_list={}
				end--end of if #ip_list>=15
			end--end of for
			--处理剩余不足15个ip
			print('begin thread last_hop',ip_count)
			for i in pairs(ip_list) do
				local last_hop_co = stdnse.new_thread(last_hop,ip_list[i],iface,last_hop_result)
				last_hop_thread_handler[last_hop_co]=true
			end
			
		    repeat
		        for thread in pairs(last_hop_thread_handler) do
		            if coroutine.status(thread) == "dead" then
		                last_hop_thread_handler[thread] = nil
		            end
		        end
		        if (next(last_hop_thread_handler)) then
		            last_hop_condvar "wait"
		        end
		    until next(last_hop_thread_handler) == nil
		end
		-- last_hop_main(dst_ip,iface)
		send_l3_sock:ip_close()
		print('fastrace last_hop end')
		print("__________________")
		return true
	end
	--针对单个ip的正常traceroute
	-- rpk_type,from= hopping(dst_ip,32,1)
	-- print(rpk_type,from)
	--调用last_hop.lua
	
	-- normal_traceroute(dst_ip)
	if dst_ip then
		local cidr = str2cidr(dst_ip)
		print(cidr['ip'],cidr['fpx'])
		local temp, err = ipOps.expand_ip(cidr['ip'])
		if err then
			print("error:illege ip",cidr['ip'])
			return true
		end
		print(HOSTADDR(cidr['ip'],cidr['fpx']))
		print(NETADDR(cidr['ip'],cidr['fpx']))
		if cidr['fpx']>=32 then
			normal_traceroute(cidr['ip'])
		elseif cidr['fpx'] >=1 then
			treetrace(cidr)
		else
			print("error cidr format:",dst_ip)
		end
	elseif ip_file then 	--目标为文件
		for line in io.lines(ip_file) do
			local ip=stdnse.strsplit(" ", line)
			local cidr = str2cidr(ip[1])
			print(cidr['ip'],cidr['fpx'])
			local temp, err = ipOps.expand_ip(cidr['ip'])
			if not err then
				print(HOSTADDR(cidr['ip'],cidr['fpx']))
				print(NETADDR(cidr['ip'],cidr['fpx']))
				if cidr['fpx']>=32 then
					normal_traceroute(cidr['ip'])
				elseif cidr['fpx'] >=1 then
					treetrace(cidr)
				else
					print("error cidr format:",ip[1],cidr['ip'],cidr['fpx'])
				end
			else
				print("error:illege ip",cidr['ip'])
			end
		end--end for
	else
	end
	-- local s = Stack:new()
	-- s:push(1)
	-- s:push(2)
	-- print(s:top())
	-- s:printElement()
	send_l3_sock:ip_close()

	return true
end