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
-- local datetime = require "datetime"
-- local io = require "io"
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
	pi['type']=send_packet_type
	pi['rtt']=0
	pi['repy_ttl']=0
	local rpk_type=0
	local from
	local rtt
	local reply_ttl
	if send_packet_type==PPK_ICMPECHO then		--3
		---print("probe type:PPK_ICMPECHO")
		rpk_type, from,rtt,reply_ttl=prober.send_icmp_echo(pi,send_l3_sock,iface.device)
	elseif send_packet_type==PPK_ACK then
		---print("probe type:PPK_TCP_ACK")	--效果不佳
		rpk_type, from,rtt,reply_ttl=prober.send_tcp_ack(pi,send_l3_sock,iface.device)
	elseif send_packet_type==PPK_SYN then
		---print("probe type:PPK_TCP_SYN")
		rpk_type, from,rtt,reply_ttl=prober.send_tcp_syn(pi,send_l3_sock,iface.device)
	elseif send_packet_type==PPK_FIN then
		---print("probe type:PPK_TCP_FIN")	--效果很差
		rpk_type, from,rtt,reply_ttl=prober.send_tcp_fin(pi,send_l3_sock,iface.device)
	elseif send_packet_type==PPK_UDPBIGPORT then
		---print("probe type:PPK_UDPBIGPORT")
		rpk_type, from,rtt,reply_ttl=prober.send_udp_big_port(pi,send_l3_sock,iface.device)
		-- print("probe result:rpk_type,from:",rpk_type,from)
	end
	if VERBOSE == 1 then
		print_ri(pi,rpk_type,from,rtt,reply_ttl)
	end
	return rpk_type,from,rtt,reply_ttl
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
	local rtt
	local reply_ttl
	try =3
	trace['rst']=0
	if trace['end'] > MAX_HOP then
		trace['end'] = MAX_HOP
	end
	ttl=trace['end']	--trace->end = trace->start - 1;  trace->start = cmptrace->end;
	while ttl ~=0 do
		rpk_type,from,rtt,reply_ttl=hopping(trace['dst'],ttl,try)
		trace['rtt']=rtt
		trace['reply_ttl']=reply_ttl
		if rpk_type ==0 then
			return -1
		end
		if rpk_type == RPK_TIMEOUT then
			---print("*HOP:",ttl,"timeout:",timeout)
			trace['hop'][ttl]=0
			-- ttl=ttl-1
			goto reverse_hopping_begin
		end
		timeout=0
		trace['hop'][ttl] = from
		if rpk_type ~= RPK_TIMEEXC then
			if IS_UNREACH(rpk_type) == 1 then 		--0 and 1 for lua is true
				code=rpk_type - RPK_UNREACH
				if code ~= ICMP_PROT_UNREACH and code ~= ICMP_PORT_UNREACH then
					trace['rst'] = TR_RESULT_UNREACH
		        	if VERBOSE == 1 then
		        		print("reverse_traceroute NOT_RPK_TIMEEXC IS_UNREACH TR_RESULT_UNREACH")
		        	end
				else
					---print(">HOP:",ttl,"get target:",from)
					trace['rst'] = TR_RESULT_GOTTHERE
		        	if VERBOSE == 1 then
		        		print("reverse_traceroute NOT_RPK_TIMEEXC IS_UNREACH ICMP_PROT_UNREACH or ICMP_PORT_UNREACH")
		        	end
				end
			else
				---print(">HOP:",ttl,"get target:",from)
	        	if VERBOSE == 1 then
	        		print("reverse_traceroute NOT_RPK_TIMEEXC NOT_IS_UNREACH")
	        	end
				trace['rst'] = TR_RESULT_GOTTHERE
			end
            --/* If `ttl' isn't equal to `trace->end', it means:
            -- * When we had found some routers on farther hops, we got a 
            -- * finished return packet. This may be caused by a too large 
            -- * end TTL value or Amazing! We change end TTL value
            -- */
            trace['end']=ttl
            goto reverse_hopping_begin
        end
        ---print(">HOP:",ttl,"from:",from)
        --错误的报文
        if from == trace['dst'] then
        	---print("!TR_RESULT_FAKE:",ttl,"from:",from)
        	trace['end'] = ttl
        	trace['rst'] = TR_RESULT_FAKE
        	-- ttl=ttl-1
        	if VERBOSE == 1 then
        		print("reverse_traceroute TR_RESULT_FAKE")
        	end
        	goto reverse_hopping_begin
        end
        if cmptrace ~= nil and cmptrace['start'] <= ttl and cmptrace['end'] >= ttl and cmptrace['hop'][ttl] == trace['hop'][ttl] then
        	trace['start'] = ttl
			if trace['rst'] == 0 then		--仅当没有TR_RESULT_GOTTHERE和TR_RESULT_FAKE
				---print("TR_RESULT_DESIGN:",ttl,"from:",from)
				trace['rst'] = TR_RESULT_DESIGN
			end
			if VERBOSE == 1 then
				print("reverse_traceroute BNP ,current",ttl,"cmptrace start,end ttl:",cmptrace['start'],cmptrace['end'],"rst:",trace['rst'])
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
	local rtt
	local reply_ttl
	try=3					--更改发包类型,lua，table下标从0开始
	if cmptrace then
		if trace['start']==0 then 				--treetrace->forward_reverse->this
			trace['start']=cmptrace['end']		--从cmptrace end处开始,继续增加ttl探测
			compare_each_from=0
		else
			compare_each_from=1
		end
	end
	ttl=trace['start']
	trace['hop']={}
	---print("forward_traceroute:")
	while ttl <= MAX_HOP do
		-- print("begin:",timeout,timeout_hops)
		if timeout >=1 or timeout_hops>=1 then
			try=GET_TRY(try)
		end
		-- print("begin hopping:",rpk_type,from)
		rpk_type,from,rtt,reply_ttl=hopping(trace['dst'],ttl,try)
		trace['rtt']=rtt
		trace['reply_ttl']=reply_ttl
		-- print("hopping:",rpk_type,from)
		if rpk_type==0 then
			---print("forward_traceroute stop because rpk_type 0!")
			return -1
		end
		--超时未响应
		if rpk_type==RPK_TIMEOUT then
			timeout=timeout+1
			---print("*HOP:",ttl,"timeout:",timeout,timeout_hops)
			if compare_each_from == 0 and cmptrace ~=nil then
				--TODO:近邻无应答结束技术 NNS
				--1.如果cmptrace当前hop超时，那此hop也超时
				--2.如果 cmptrace 以响应超时结束，此结果也是超时
				--近邻无应答结束技术 NNS
				if cmptrace['end'] == ttl and cmptrace['rst'] == TR_RESULT_TIMEOUT then
					trace['hop'][ttl]=0
					trace['end']=ttl
					trace['rst']=TR_RESULT_TIMEOUT
					if VERBOSE == 1 then
						print("NNS forward_traceroute")
					end
					return 1
				end
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
					if VERBOSE == 1 then
						print("forward_traceroute TR_RESULT_TIMEOUT ttl:",ttl,"timeout_hops:",timeout_hops)
					end
					---print("!TR_RESULT_TIMEOUT:",ttl,"timeout:",timeout,timeout_hops)
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
			if ttl>2 and from ~= trace['hop'][ttl-1] then 	--相邻两跳相同不算
				local i
				for i=trace['start'],ttl - 2 do 		--从start到ttl-2 与from对比，查看是否一致
					if from==trace['hop'][i] then	--
						trace['end']=ttl
						trace['rst']=TR_RESULT_LOOP
						if VERBOSE == 1 then
							print("forward_traceroute TR_RESULT_LOOP ")
						end
						---print("TR_RESULT_LOOP:",ttl,"from:",from)
						return 1
					end
				end
			end		--end if ttl>2 and from ~= trace['hop'][ttl-2]
			if from == trace['dst'] then		--生存时间超时，却是目标发送的
				---print("!TR_RESULT_FAKE:",ttl,"from:",from)
				trace['end']=ttl
				trace['rst']=TR_RESULT_FAKE
				return 1
			end		--end if from == trace['dst']
			if cmptrace ~= nil then
				--TODO:treetrace
				--trace->start==1,
				if compare_each_from == 1 then
					for i = cmptrace['start'] , cmptrace['end'] do
						--ttl从1开始探测时，在from对应ttl时，发现与cmptrace一致的结果，
						if from == cmptrace['hop'][i] then
							trace['end'] = ttl
							trace['rst'] = TR_RESULT_DESIGN
							if VERBOSE == 1 then
								print("forward_traceroute TR_RESULT_DESIGN compare_each_from,current ttl:",ttl,"cmptrace hop:",i)
							end
							--TODO:right or not
							for j = ttl + 1 , cmptrace['end'] - i + ttl  do 	--将i之后的结果，拷贝到trace中
								trace['hop'][j] = cmptrace[hop][i+j-ttl]
							end
							return 1
						end
					end
				else
					--trace['start'] = cmptrace['end']
					if cmptrace['rst'] == TR_RESULT_LOOP and cmptrace['end'] == ttl and cmptrace['hop'][ttl] == trace['hop'][ttl] then
						trace['end'] = ttl
						trace['rst'] = TR_RESULT_LOOP
						if VERBOSE == 1 then
							print("forward_traceroute TR_RESULT_LOOP by cmptrace")
						end
						return 1
					end
				end
			end
			---print(">HOP:",ttl,"from:",from)
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
				if VERBOSE == 1 then
					print("forward_traceroute TR_RESULT_UNREACH return")
				end
				return 1
			end
		end	--end if(is_unreach(rpk_type))
		--排除超时未响应，ICMP生存时间超时，ICMP目标不可达(除去端口不可达、协议不可达)，返回包类型可能为：
		--1.ICMP echo reply,端口不可达，协议不可达
		--2.TCP RPK_RST	,RPK_SYNACK	,RPK_RSTACK
		do
			trace['end']=ttl
			trace['rst']=TR_RESULT_GOTTHERE
			---print(">HOP:",ttl,"get target:",from)
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
	if VERBOSE == 1 then
		print("forward_traceroute MAX_HOP return")
	end
	return 1
end
--检查路径是否循环
function search_loop(trace)
	local i,j
	for i = (trace['start']+2) , trace['end'] do
		if trace['hop'][i] == trace['hop'][i-1] then
			-- print('')
		else
			j=i-2
			while j >= trace['start'] do
				if trace['hop'][i] == trace['hop'][j] then
					trace['rst'] = TR_RESULT_LOOP
					trace['end'] =i
					return 1
				end
				j = j - 1
			end--end while
		end
	end--end for
	return 0
end
function forward_reverse(trace,fcmptrace,rcmptrace)
	local result
	local fend
	if forward_traceroute(trace,fcmptrace) == -1 then
		return -1
	end
	if trace['start'] ==1 then 		--fcmptrace end ==1
		--/* NO less TTL value for reverse_traceroute(). */
		return 1
	end
	result = trace['rst']
	fend = trace['end']
	trace['end'] = trace['start'] -1

	if reverse_traceroute(trace,rcmptrace) ==-1 then 	--start=1 for reverse_traceroute
		return -1
	end
	if trace['rst'] ~= TR_RESULT_DESIGN then
		return 1
	end
	if result == TR_RESULT_TIMEOUT then
		local i = fend 
		while i>0 and trace['hop'][i] ==0 do 			--table begin from 1,找到第一个超时的，即为end
			i=i-1
		end
		fend = i + 1
	end
	trace['rst'] = result
	trace['end'] = fend
	if result == TR_RESULT_LOOP or result == TR_RESULT_MAXHOP then
		search_loop(trace)
	end
	return 1
end
local function normal_traceroute(dst_ip)
	local trace={}
	trace['dst']=dst_ip
	trace['start']=1
	forward_traceroute(trace,nil)
end
local function copy_tracehop(tracedst,tracesrc,ttls,ttle)
	--copy from reverse_traceroute
	for i=ttls,ttle do
		tracedst['hop'][i] = tracesrc['hop'][i]
	end
	tracedst['start']=ttls
end
local function compare_endrouter(trace1,trace2)
	if trace1['rst'] == TR_RESULT_DESIGN or trace2['rst'] == TR_RESULT_DESIGN then
		return -1
	end
	if trace1['end'] < 2 then
		return 0
	end
	if trace1['end'] == trace2['end'] then 
		if trace1['hop'][trace1['end'] - 1] == trace2['hop'][trace2['end'] - 1] then
			return 0
		else
			return 1
		end
	end
	return 1
	-- body
end
local function treetrace(cidr)
	-- print("verbose:",VERBOSE)
	--newsr=(fpx => 24,
	--		 trace =>(
	--		 		dst => 192.168.121.1,
	--		 		start => 1,
	--		 		hop =>[],
	--		 		end =>3,
	--		 		rst =>1)
	--		 )
	--		)
	local newsr = {}
	local oldsr = {}
	newsr['trace']={}
	oldsr['trace']={}
	if cidr['pfx']>=MAX_PREFIX_LEN then
		if (cidr['pfx'] ~=32) and (HOSTADDR(cidr['net'],cidr['pfx'])==0) then
			cidr['net']=IP_INC(cidr['net'])
		end
		normal_traceroute(cidr['net'])
		return
	end
	newsr['pfx']=cidr['pfx']
	newsr['trace']['dst']=IP_INC(NETADDR(cidr['net'],cidr['pfx']))
	newsr['trace']['start'] = 1
	-- print(newsr['trace']['dst'],newsr['trace']['start'])
	if VERBOSE == 1 then
		io.write("Fastrace ",newsr['trace']['dst'],"/",newsr['pfx']," at ",os.date("%Y-%m-%d %H:%M:%S"),"\n")
	end
	if forward_traceroute(newsr['trace'],nil)==-1 then
		newsr=nil
		return
	end

	local s = Stack:new()
	s:push(newsr)
	while s:is_empty() == false do
		oldsr = s:top()
		-- print('addr:',oldsr,newsr)
		newsr = {} 		--赋为空后，地址改变，不再和oldsr指向同一地址
		-- print('addr:',oldsr,newsr)
		-- for k,v in pairs(oldsr) do
		-- 	print(k,v)
		-- 	if k=='trace' then
		-- 		for i,j in pairs(v) do
		-- 			print(i,j)
		-- 		end
		-- 	end
		-- end
		newsr['trace']={}
		if HOSTADDR(oldsr['trace']['dst'],oldsr['pfx'])  == 1 then
			newsr['trace']['dst'] = IP_DEC(NETADDR(oldsr['trace']['dst'],oldsr['pfx']) + bit.rshift(0xffffffff,oldsr['pfx']))
		else
			newsr['trace']['dst'] = IP_INC(NETADDR(oldsr['trace']['dst'],oldsr['pfx']))
		end 
		newsr['trace']['start'] = 0			--/* `start' waiting to be set by `oldsr'. */
		if VERBOSE == 1 then 
			io.write('get oldsr on top stack:',oldsr['trace']['dst'],"/",oldsr['pfx'],"\n")
			io.write('get newsr by oldsr:',newsr['trace']['dst'],"/",oldsr['pfx'],"\n")
			io.write("Fastrace ",newsr['trace']['dst'],"/",oldsr['pfx']," at ",os.date("%Y-%m-%d %H:%M:%S"),"\n")
		end
		if forward_reverse(newsr['trace'],oldsr['trace'],oldsr['trace']) == -1 then
			s:clear()
			return
		end
		copy_tracehop(newsr['trace'],oldsr['trace'],1,newsr['trace']['start']-1)
		if newsr['trace']['rst'] == TR_RESULT_LOOP or newsr['trace']['rst'] ==TR_RESULT_MAXHOP then
			search_loop(newsr['trace'])
		end
		--比较末跳路由，如果一致，则认为在同一子网
		if compare_endrouter(newsr['trace'],oldsr['trace']) == 0 and oldsr['pfx'] >= MIN_PREFIX_LEN then
			s:pop()
			print("SAME SUBNET:",fastrace_fromdword(NETADDR(oldsr['trace']['dst'],oldsr['pfx'])),oldsr['pfx'])
			print_tr(oldsr['trace'])
			oldsr={}
			newsr={}
			goto TREETRACE_WHILE
		end
		--TODO: Min non-new netmark prefix lenth. 

		if (oldsr['pfx'] + 1) >= MAX_PREFIX_LEN then
			s:pop()
			print("SUBNET max prefix lenth:",fastrace_fromdword(NETADDR(oldsr['trace']['dst'],oldsr['pfx']+1)),oldsr['pfx']+1)
			print_tr(oldsr['trace'])
			--TODO:last_hop_test
			print("SUBNET max prefix lenth:",fastrace_fromdword(NETADDR(newsr['trace']['dst'],oldsr['pfx']+1)),oldsr['pfx']+1)
			print_tr(newsr['trace'])
			oldsr={}
			newsr={}
			goto TREETRACE_WHILE
		end
		oldsr['pfx']=oldsr['pfx']+1
		newsr['pfx']=oldsr['pfx']
		s:push(newsr)
		print("Stack PUSH",newsr['trace']['dst'],newsr['pfx'])
		::TREETRACE_WHILE::
	end --end for while
	s:clear()
end

local function last_hop(dst_ip,iface,result)
	local last_hop_condvar = nmap.condvar(result)
	print('target:',dst_ip)
	last_hop_main(dst_ip,iface)
	print('end:',dst_ip)
	last_hop_condvar "signal"
end
local function test(point)
	point['a']=1
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
	-- verbose=0
	VERBOSE=stdnse.get_script_args("verbose")

	if VERBOSE ~=nil then
		if VERBOSE ~= '1' and VERBOSE ~= '0' then
			return print("error:verbose param error",VERBOSE)
		else
			VERBOSE=tonumber(VERBOSE)
		end
	else
		VERBOSE=0
	end
	print("verbose:",VERBOSE)
	-- VERBOSE=1
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
	-- local tp={}
	-- tp['point']={}
	-- test(tp['point'])
	-- print(tp['point']['a'])

	if dst_ip then
		local cidr = str2cidr(dst_ip)
		print(cidr['net'],cidr['pfx'])
		local temp, err = ipOps.expand_ip(cidr['net'])
		if err then
			print("error:illege ip",cidr['net'])
			return true
		end
		-- print(HOSTADDR(cidr['net'],cidr['pfx']))
		-- print(NETADDR(cidr['net'],cidr['pfx']))
		if cidr['pfx']>=32 then
			normal_traceroute(cidr['net'])
		elseif cidr['pfx'] >=1 then
			treetrace(cidr)
		else
			print("error cidr format:",dst_ip)
		end
	elseif ip_file then 	--目标为文件
		for line in io.lines(ip_file) do
			local ip=stdnse.strsplit(" ", line)
			local cidr = str2cidr(ip[1])
			-- print(cidr['net'],cidr['pfx'])
			local temp, err = ipOps.expand_ip(cidr['net'])
			if not err then
				-- print(HOSTADDR(cidr['net'],cidr['pfx']))
				-- print(NETADDR(cidr['net'],cidr['pfx']))
				if cidr['pfx']>=32 then
					normal_traceroute(cidr['net'])
				elseif cidr['pfx'] >=1 then
					treetrace(cidr)
				else
					print("error cidr format:",ip[1],cidr['net'],cidr['pfx'])
				end
			else
				print("error:illege ip",cidr['net'])
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