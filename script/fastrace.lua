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
local bit = require "bit"
local json = require "json"
-- local datetime = require "datetime"
-- local io = require "io"
require('base')			--包含基础函数，全局变量
require('prober')		--包含发包模块
require('last_hop')		--包含末跳模块
require('unit_test')
local quicktrace = require('quicktrace')	--包含quicktrace模块
local last_N_hop = require('last_N_hop')	--包含探测倒数n跳模块
local Stack=require('stack')				--包含栈结构


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

-- prerule=function(host)
-- 	return true
-- end
hostrule=function(host)
	--print("hostrule:",host.ip)
	return true
end
portrule = function(host)
	return true
end

local function fail(err) return ("\n  ERROR: %s"):format(err or "") end

--末跳上超时时，更换探测包，try为探测包类型数组下标
--每次递增1
local function GET_TRY(try)
	if try >= NR_PROBING_ARRAY then
		try = 2
	else
		try=try+1
	end
	return try
end

--发包入口函数，函数参数：目的ip,设置TTL,try:探测包类型
local function hopping(dst_ip,ttl,try)
	ALL_SEND_PACKET=ALL_SEND_PACKET+1
	local pi={}		--探测信息
	-- print(try)
	--error:设置不同类型时，端口也得改变，改变try即可
	if PACKET_TYPE == "ICMP" then
		-- send_packet_type=PPK_ICMPECHO
		try=3
	elseif PACKET_TYPE == "UDP" then
		-- send_packet_type=PPK_UDPBIGPORT
		try=2
	elseif PACKET_TYPE == "TCP" then
		-- send_packet_type=PPK_SYN
		try=1
	else
	end
	local send_packet_type=PROBING_TYPE_ARRAY[try]
	--不同探测包类型，选择的端口号不一样
	pi['dport']=PROBING_DPORT_ARRAY[try]
	pi['dport']=PROBING_DPORT_ARRAY[try]
	pi['sport']=math.random(0x7000, 0xffff)		--why from 7000
	pi['wt']=2000								--wait time
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

	if VERBOSE >= 1 then
		print_ri(pi,rpk_type,from,rtt,reply_ttl)
	end
	-- if rpk_type ~= RPK_TIMEOUT then
	-- 	if global_node[from] == nil then
	-- 		-- print("why ",from)
	-- 		ALL_NODE = ALL_NODE +1
	-- 		--若为中间路由器
	-- 		if from ~= dst_ip then
	-- 			MID_ROUTER_COUNT=MID_ROUTER_COUNT+1
	-- 		end
	-- 	end
	-- 	EVERY_TATGET_SEND[ALL_NODE]=ALL_SEND_PACKET

	-- 	MID_ROUTER_SEND[MID_ROUTER_COUNT]=ALL_SEND_PACKET
	-- end
	return rpk_type,from,rtt,reply_ttl
	-- body
end

--/* Reverse version of forward_traceroute(), not TTL++ but TTL--. 
-- * TTL start from `trace'->end, and destination host is `trace'->dst.
-- * Traceroute finished until TTL == 1 or found the same router as `cmptrace'
-- * on the same hop.
-- */
--//BNP backward on neighbor’s path
--反向探测模块，从cmptrace->end，也是trace['end']开始，ttl递减探测
--直到同一跳遇到相同的路由器接口，停止探测
local function reverse_traceroute(trace,cmptrace)
	local ttl
	local rpk_type				--返回包类型
	local code					--ICMP错误代码
	local from					--探测回复的源ip
	local rtt
	local reply_ttl
	local timeout=0
	try =2
	trace['rst']=0
	if trace['end'] > MAX_HOP then
		trace['end'] = MAX_HOP
	end
	ttl=trace['end']	--trace->end = trace->start - 1;  trace->start = cmptrace->end;
	while ttl ~=0 do
		rpk_type,from,rtt,reply_ttl=hopping(trace['dst'],ttl,try)
		if rpk_type ==0 then
			return -1
		end
		-- if rpk_type == RPK_TIMEOUT then
		-- 	---print("*HOP:",ttl,"timeout:",timeout)
		-- 	trace['hop'][ttl]=0
		-- 	trace['rtt'][ttl]=0
		-- 	trace['reply_ttl'][ttl]=0
		-- 	goto reverse_hopping_begin
		-- end
		--超时未响应
		if rpk_type==RPK_TIMEOUT then
			timeout=timeout+1
			--更换探测包
			try = GET_TRY(try)
			if timeout >= MAX_TIMEOUT_PER_HOP then	--一跳上连续 MAX_TIMEOUT_PER_HOP 次超时，探测下一跳
				timeout=0
				try=2 		--重置为2
				trace['hop'][ttl]=0
				trace['rtt'][ttl]=0
				trace['reply_ttl'][ttl]=0
			else
				ttl=ttl+1 		--超时未到达上限，继续本跳探测
			end	--end timeout==MAX_TIMEOUT_PER_HOP
			-- ttl=ttl+1
			--进行下一次while循环
			goto reverse_hopping_begin
		end		--end rpk_type==RPK_TIMEOUT
		--未超时，写入探测信息，重置超时计数器 
		timeout=0
		trace['hop'][ttl] = from
		trace['rtt'][ttl]=rtt
		trace['reply_ttl'][ttl]=reply_ttl
		if rpk_type ~= RPK_TIMEEXC then
			--是ICMP不可达消息
			if IS_UNREACH(rpk_type) == 1 then 		--0 and 1 for lua is true
				code=rpk_type - RPK_UNREACH
				--仅当是端口不可达或协议不可达，才认为是目标回复
				if code ~= ICMP_PROT_UNREACH and code ~= ICMP_PORT_UNREACH then
					trace['rst'] = TR_RESULT_UNREACH
		        	if VERBOSE >= 1 then
		        		print("reverse_traceroute NOT_RPK_TIMEEXC IS_UNREACH TR_RESULT_UNREACH")
		        	end
				else
					--仅当是端口不可达或协议不可达，才认为是目标回复
					---print(">HOP:",ttl,"get target:",from)
					trace['rst'] = TR_RESULT_GOTTHERE
		        	if VERBOSE >= 1 then
		        		print("reverse_traceroute ,NOT RPK_TIMEEXC ,IS_UNREACH ,ICMP_PROT_UNREACH or ICMP_PORT_UNREACH, TR_RESULT_GOTTHERE")
		        	end
				end
			else
				--如果不是ICMP不可达，也不是生存时间超时，认为本跳到达目标
				---print(">HOP:",ttl,"get target:",from)
	        	if VERBOSE >= 1 then
	        		print("reverse_traceroute ,NOT RPK_TIMEEXC ,NOT IS_UNREACH ,TR_RESULT_GOTTHERE")
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
        --到这里，认为是生存时间超时消息
        ---print(">HOP:",ttl,"from:",from)
        --错误的报文：是生存时间超时，但是源IP为目标
        if from == trace['dst'] then
        	---print("!TR_RESULT_FAKE:",ttl,"from:",from)
        	trace['end'] = ttl
        	trace['rst'] = TR_RESULT_FAKE
        	-- ttl=ttl-1
        	if VERBOSE >= 1 then
        		print("reverse_traceroute, TR_RESULT_FAKE")
        	end
        	goto reverse_hopping_begin
        end
        --BNP,在相同跳上，遇到与参考路径相同的路由器接口
        if cmptrace ~= nil and cmptrace['start'] <= ttl and cmptrace['end'] >= ttl and cmptrace['hop'][ttl]~=0 and cmptrace['hop'][ttl] == trace['hop'][ttl] then
        	trace['BNP']=ttl
        	trace['start'] = ttl
			if trace['rst'] == 0 then		--仅当没有TR_RESULT_GOTTHERE和TR_RESULT_FAKE
				---print("TR_RESULT_DESIGN:",ttl,"from:",from)
				trace['rst'] = TR_RESULT_DESIGN
			end
			if VERBOSE >= 1 then
				io.write("reverse_traceroute BNP, ","current ip has same hop with cmptrace on ttl = ",ttl," return\n")
			end
			--记录目标网段BNP次数，测试用
			BNP_COUNT=BNP_COUNT+1
			return 1
		end
		::reverse_hopping_begin::
		ttl=ttl-1
	end
	if VERBOSE >= 1 then
		io.write("reverse_traceroute ttl arrive 1, return\n")
	end
	--探测直到退出while循环，说明ttl递减到0了，设置start=1
	trace['start']=1
	if trace['rst'] == 0 then
		trace['rst'] = TR_RESULT_DESIGN
	end
	return 1
end
--正向探测，ttl从cmptrace['end']递增探测
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
	try=2					--默认发包类型为icmp,lua，table下标从1开始
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
	trace['rtt']={}
	trace['reply_ttl']={}
	---print("forward_traceroute:")
	while ttl <= MAX_HOP do
		-- print("begin:",timeout,timeout_hops)
		--本跳超时，更换探测包
		if timeout >=1 or timeout_hops>=1 then
			try=GET_TRY(try)
		end
		-- print("begin hopping:",rpk_type,from)
		--在本跳上发包
		rpk_type,from,rtt,reply_ttl=hopping(trace['dst'],ttl,try)
		-- print("hopping:",rpk_type,from)
		--收到未知错误报文，退出探测，很少发生
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
				--1.如果cmptrace在最后一跳是超时结算，而未到达目标
				--2.目标此跳也超时，则认为目标和cmptrace一样也不可达，退出
				--近邻无应答结束技术 NNS
				--问题：可能刚好在这一跳上超时，导致部分目标未发现，注注释338行取消NNS，以发现完整目标
				if cmptrace['end'] == ttl and cmptrace['rst'] == TR_RESULT_TIMEOUT then
					trace['hop'][ttl]=0
					trace['rtt'][ttl]=0
					trace['reply_ttl'][ttl]=0

					trace['end']=ttl
					trace['rst']=TR_RESULT_TIMEOUT
					if VERBOSE >= 1 then
						io.write("forward_traceroute NNS by cmptrace, cmptrace stop on this ttl timeout, and this ip ",trace['dst']," timeout as well as cmptrace on this ttl= ",ttl,", NNS stop.\n")
					end
					NNS_COUNT=NNS_COUNT+1
					--注释下面一行，表示不使用NNS
					-- return 1
				end
			end

			if timeout==MAX_TIMEOUT_PER_HOP then	--一跳上连续 MAX_TIMEOUT_PER_HOP 次超时，探测下一跳
				timeout=0
				try=2
				timeout_hops=timeout_hops+1
				trace['hop'][ttl]=0
				trace['rtt'][ttl]=0
				trace['reply_ttl'][ttl]=0
				if timeout_hops>=MAX_TIMEOUT_HOPS then	--连续MAX_TIMEOUT_HOPS跳超时，退出对目标的探测，否则进行下一跳
					--Too many continuous timeout.
					--Remain a router ZERO at the end of path.
					trace['end']=ttl - MAX_TIMEOUT_HOPS+1
					trace['rst']=TR_RESULT_TIMEOUT
					if timeouth>=1 then
						print("TOH OK")
					end
					if VERBOSE >= 1 then
						io.write("forward_traceroute TR_RESULT_TIMEOUT, ttl:",ttl," no result ON continue ",timeout_hops,"hops, stop.\n")
					end
					---print("!TR_RESULT_TIMEOUT:",ttl,"timeout:",timeout,timeout_hops)
					return 1
				end		--end timeout_hops==MAX_TIMEOUT_HOPS
				-- try=2
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
		trace['rtt'][ttl]=rtt
		trace['reply_ttl'][ttl]=reply_ttl
		if rpk_type == RPK_TIMEEXC then
			--检查是否遇到环路
			if ttl>2 and from ~= trace['hop'][ttl-1] then 	--相邻两跳相同不算
				local i
				for i=trace['start'],ttl - 2 do 		--从start到ttl-2 与from对比，查看是否一致
					if from==trace['hop'][i] then	--
						trace['end']=ttl
						trace['rst']=TR_RESULT_LOOP
						if VERBOSE >= 1 then
							io.write("forward_traceroute TR_RESULT_LOOP, ttl from ",i," to ",ttl," LOOP\n")
						end
						---print("TR_RESULT_LOOP:",ttl,"from:",from)
						return 1
					end
				end
			end		--end if ttl>2 and from ~= trace['hop'][ttl-2]
			if from == trace['dst'] then		--生存时间超时，却是目标发送的，认为错误报文
				---print("!TR_RESULT_FAKE:",ttl,"from:",from)
				trace['end']=ttl
				trace['rst']=TR_RESULT_FAKE
				return 1
			end		--end if from == trace['dst']
			if cmptrace ~= nil then
				--TODO:treetrace
				--trace->start==1,
				--这个条件从未满足，if 函数体不执行，不清楚干啥的
				if compare_each_from == 1 then
					for i = cmptrace['start'] , cmptrace['end'] do
						--ttl从1开始探测时，在from对应ttl时，发现与cmptrace一致的结果，
						if from == cmptrace['hop'][i] then
							trace['end'] = ttl
							trace['rst'] = TR_RESULT_DESIGN
							if VERBOSE >= 1 then
								io.write("forward_traceroute TR_RESULT_DESIGN, compare_each_from,current ttl: ",ttl," cmptrace hop:",i," .\n")
							end
							--TODO:right or not
							for j = ttl + 1 , cmptrace['end'] - i + ttl  do 	--将i之后的结果，拷贝到trace中
								trace['hop'][j] = cmptrace[hop][i+j-ttl]
								trace['rtt'][j]=cmptrace['rtt'][i+j-ttl]
								trace['reply_ttl'][j]=cmptrace['reply_ttl'][i+j-ttl]
							end
							return 1
						end
					end
				else
					--trace['start'] = cmptrace['end']
					--如果cmptrace因环路结束，目标在cmptrace.ttl=end 遇到相同路由器接口，认为也是环路，结束
					if cmptrace['rst'] == TR_RESULT_LOOP and cmptrace['end'] == ttl and cmptrace['hop'][ttl] == trace['hop'][ttl] then
						trace['end'] = ttl
						trace['rst'] = TR_RESULT_LOOP
						if VERBOSE >= 1 then
							io.write("forward_traceroute TR_RESULT_LOOP by cmptrace, cmptrace stop by LOOP on ",ttl," and both hop same on the ttl,stop.\n")
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
			--不是端口不可达和协议不可达的，都停止探测，以不可达结束，端口不可达和协议不可达认为是目标的回复，到达目标
			if code ~=  ICMP_PROT_UNREACH  and  code ~= ICMP_PORT_UNREACH then
				trace['end'] = ttl
				trace['rst'] = TR_RESULT_UNREACH
				if VERBOSE >= 1 then
					print("forward_traceroute TR_RESULT_UNREACH, receive icmp unreach message, return.")
				end
				return 1
			end
		end	--end if(is_unreach(rpk_type))
		--排除超时未响应，ICMP生存时间超时，ICMP目标不可达(除去端口不可达、协议不可达)，返回包类型可能为：
		--1.ICMP echo reply,端口不可达，协议不可达
		--2.TCP RPK_RST	,RPK_SYNACK	,RPK_RSTACK
		--认为到达目标，结束正向探测
		do
			trace['end']=ttl
			trace['rst']=TR_RESULT_GOTTHERE
			if VERBOSE >= 1 then
				io.write("forward_traceroute TR_RESULT_GOTTHERE, ttl= ",ttl, " arrive target, return.\n")
			end
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
	if VERBOSE >= 1 then
		print("forward_traceroute arrive MAX_HOP return.")
	end
	return 1
end
--检查路径是否循环
function search_loop(trace)
	local i,j
	for i = (trace['start']+2) , trace['end'] do
		--i跳为0，跳过，无需比较
		if trace['hop'][i] ~= 0 or trace['hop'][i] == trace['hop'][i-1] then
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
--正向反向探测：
--1.以rcmptrace的ttl=end开始正向探测forward_traceoute
--2.以rcmptrace的ttl=end开始，反向探测reverse_traceroute
function forward_reverse(trace,fcmptrace,rcmptrace)
	local result
	local fend
	--开始正向探测
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
	--开始反向探测
	if reverse_traceroute(trace,rcmptrace) ==-1 then 	--start=1 for reverse_traceroute
		return -1
	end

	if trace['rst'] ~= TR_RESULT_DESIGN then 			--trace['rst']=TR_RESULT_GOTTHERE，原因能是：在 reverse_traceroute 中到达目标 TR_RESULT_GOTTHERE
		if VERBOSE >=1 then
			io.write('forward_reverse, arrive target in reverse_traceroute,real end: ',trace['end']," before end: ",fend,"\n")
		end
		return 1
	end
	--在正向探测时，因超时停止探测，找到最小超时的ttl，作为结束时的ttl
	if result == TR_RESULT_TIMEOUT then
		local i = fend 
		while i>0 and trace['hop'][i] ==0 do 			--table begin from 1,找到第一个超时的，即为end
			i=i-1
		end
		fend = i + 1
	end
	trace['rst'] = result
	trace['end'] = fend
	--查找环路，删除环路
	if result == TR_RESULT_LOOP or result == TR_RESULT_MAXHOP then
		search_loop(trace)
	end
	return 1
end
--测试停止前缀和获取节点，边，路由器接口的关系，与测量无关
local function test_max_fpx(new_link,new_node,pfx,new_router)
	for i=1, 31 do
		if pfx <=i then
			if TEST_PFX_INFO[i] ~= nil then
				TEST_PFX_INFO[i]['link']=TEST_PFX_INFO[i]['link']+new_link
				TEST_PFX_INFO[i]['node']=TEST_PFX_INFO[i]['node']+new_node
				TEST_PFX_INFO[i]['router']=TEST_PFX_INFO[i]['router']+new_router
			else
				TEST_PFX_INFO[i]={}
				TEST_PFX_INFO[i]['link']=0
				TEST_PFX_INFO[i]['node']=0
				TEST_PFX_INFO[i]['router']=0
				TEST_PFX_INFO[i]['router']=new_router
				TEST_PFX_INFO[i]['link']=TEST_PFX_INFO[i]['link']+new_link
				TEST_PFX_INFO[i]['node']=TEST_PFX_INFO[i]['node']+new_node
			end
		end
	end
end
--打印当前发现的新节点，边
local function print_all_node_link()
	print("^^^^^^^^^^^^^^^global_node^^^^^^^^^^^^^^^^^^")
	for k,v in pairs(global_node) do
		print(k)
	end
	print("^^^^^^^^^^^^^^^global_link^^^^^^^^^^^^^^^^^^")
	for k,v in pairs(global_link_hashmap) do
		print(k)
	end
end
--将对目标探测发现的新边、节点记录到全局变量：global_node，global_link_hashmap
local function get_new_link_node_number(trace,pfx)
	local new_link = 0
	local new_node = 0
	local new_router=0
	local link_key
	if DEBUG == 1 or VERBOSE>=3 then
		print("^^^^^^^^^^^^^^^global_node^^^^^^^^^^^^^^^^^^")
		for k,v in pairs(global_node) do
			print("global_node:",k)
		end
		print("^^^^^^^^^^^^^^^global_link^^^^^^^^^^^^^^^^^^")
		for k,v in pairs(global_link_hashmap) do
			print("global_link_hashmap:",k)
		end
	end
	for i = trace['start'],trace['end']-1 do
		if trace['hop'][i] ~= 0 and trace['hop'][i+1] ~= 0 then 					--中间node为 0 的略过
			if ipOps.compare_ip(trace['hop'][i],'gt',trace['hop'][i+1]) == true then
				link_key=trace['hop'][i+1]..'-'..trace['hop'][i]
			else
				link_key=trace['hop'][i]..'-'..trace['hop'][i+1]
			end
			--如果是新边，记录
			if global_link_hashmap[link_key] == nil then
				ALL_LINK=ALL_LINK+1
				new_link= new_link + 1
				global_link_hashmap[link_key] = 1
				if i == (trace['end']-1) then
					TO_TARGET_LINK=TO_TARGET_LINK+1
				end
				if DEBUG == 1 or VERBOSE>=1 then
					io.write('new link,hop: ',i," ",trace['hop'][i],' ~~~~~~~~~~~~~~~~ ',trace['hop'][i+1],"\n")
				end
				-- return 1
			end
		end
		--如果是新节点，记录
		if trace['hop'][i] ~= 0 and global_node[trace['hop'][i]] == nil then
			new_node = new_node + 1
			new_router=new_router+1
			--全局变量，统计总节点
			ALL_NODE = ALL_NODE +1
			--全部目标发包变化,第ALL_NODE个节点时，一共发了多少包
			EVERY_TATGET_SEND[ALL_NODE]=ALL_SEND_PACKET
			--路由器发包变化，发现第MID_ROUTER_COUNT个路由器接口时，一共发了多少包
			MID_ROUTER_COUNT=MID_ROUTER_COUNT+1
			MID_ROUTER_SEND[MID_ROUTER_COUNT]=ALL_SEND_PACKET
			global_node[trace['hop'][i]] = 1
			if DEBUG == 1 or VERBOSE >=1 then
				io.write('new node:',trace['hop'][i],"\n")
			end
			-- return 1
		end
	end

	--统计最后一跳的节点
	if trace['hop'][trace['end']] ~= nil and trace['hop'][trace['end']] ~= 0 and global_node[trace['hop'][trace['end']]] == nil then
		new_node = new_node + 1
		if trace['hop'][trace['end']] ~= trace['dst'] then 	--不是目标，就是路由器
			new_router=new_router+1
			MID_ROUTER_COUNT=MID_ROUTER_COUNT+1
			MID_ROUTER_SEND[MID_ROUTER_COUNT]=ALL_SEND_PACKET
		end
		ALL_NODE = ALL_NODE +1
		EVERY_TATGET_SEND[ALL_NODE]=ALL_SEND_PACKET
		global_node[trace['hop'][trace['end']]] = 1
		if DEBUG == 1 or VERBOSE >=2 then
			io.write('new node:',trace['hop'][i],"\n")
		end
		-- return 1
	end
	--统计可达目标
	if trace['hop'][trace['end']] ~= nil and trace['hop'][trace['end']] ~= 0 and trace['hop'][trace['end']] == trace['dst'] then
		TARGET_ARRIVE=TARGET_ARRIVE+1
	end
	--测试不同前缀下的边，节点获取情况
	test_max_fpx(new_node,new_link,pfx,new_router)
	if DEBUG == 1 or VERBOSE>=1 then
		print("*****packet,all link, node,mid-router, find new link, node,******",ALL_SEND_PACKET,ALL_LINK,ALL_NODE,MID_ROUTER_COUNT,new_link,new_node,"new router ",new_router)
	end
	return new_link,new_node
end
--对单个目标的traceroute
local function normal_traceroute(dst_ip)
	local trace={}
	trace['dst']=dst_ip
	trace['BNP']=0 --for print_tr error ,if not this
	trace['cmp_ip']=0 --for print_tr error ,if not this
	trace['start']=1
	if VERBOSE >= 1 then
		io.write("Fastrace ",dst_ip,"/32"," at ",os.date("%Y-%m-%d %H:%M:%S"),"\n")
	end
	forward_traceroute(trace,nil)
	get_new_link_node_number(trace,32) 		--更新已获取边，节点
	print_tr(trace,iface.address,OUTPUT_FILE_HANDLER,OUTPUT_TYPE)
end
--对于反向探测停止时，拷贝参考路径从第1跳到反向停止跳的路由器接口信息，作为目标的探测结果
local function copy_tracehop(tracedst,tracesrc,ttls,ttle)
	--copy from reverse_traceroute
	for i=ttls,ttle do
		tracedst['hop'][i] = tracesrc['hop'][i]
		tracedst['rtt'][i]=tracesrc['rtt'][i]
		tracedst['reply_ttl'][i]=tracesrc['reply_ttl'][i]
		BNP_REDUNDANCE_COUNT=BNP_REDUNDANCE_COUNT+1
	end
	tracedst['start']=ttls
end
--比较两者目标的末跳是否相同，相同返回0
local function compare_endrouter(trace1,trace2)
	--比较末跳时，必须都到达目标
	if trace1['dst'] ~= trace1['hop'][trace1['end']] or trace2['dst'] ~= trace2['hop'][trace2['end']] then
		return -1
	end

	if trace1['end'] == trace2['end'] then --IMPROVE:末跳都为零时，不算末跳相等
		if trace1['hop'][trace1['end'] - 1] ~=0 and trace1['hop'][trace1['end'] - 1] == trace2['hop'][trace2['end'] - 1] then
			return 0
		else
			return 1
		end
	end
	return 1
	-- body
end

--弃用，无意义
local function last_n_hop_is_new(trace)
	print("IMPROVE last_n_hop_is_new",IMPROVE,VERBOSE)
	for i=(trace['end']-1)-2,trace['end']-1 do
		if trace['hop'][i] ~= nil and trace['hop'][i] ~= 0 then 	--and global_node[trace['hop'][i]] == nil 
			--IMPROVE:对新发现的最后几个新发现的节点也trace
			if IMPROVE >=1 then
				if VERBOSE >= 1 then 
					-- io.write("IMPROVE last_n_hop_is_new, end: ",trace['end'],"hop ",i," :","\n")
					io.write("IMPROVE last_n_hop_is_new, end: ",trace['end'],"hop ",i," :",trace['hop'][i],"\n")
				end
				local qtrace=quicktrace.quicktrace_main(trace['hop'][i],iface,VERBOSE)
				get_new_link_node_number(qtrace,1)		--再次统计新节点和边
				print_tr(qtrace,iface.address,OUTPUT_FILE_HANDLER,OUTPUT_TYPE)
			end
			-- ALL_NODE = ALL_NODE +1
			-- global_node[trace['hop'][i]] = 1
			-- return 1
		end
	end
end
--在前缀为prefix停止继续探测时，直接对prefix构成的网段在第hop跳前后两跳的探测，hop为到达该网段目标的跳数
--以降低发包量，不用对网段内目标进行完整的tracroute，但这种改善没有理论依据
--子网探测已弃用这种方法
local function quicktrace_subnet(ip,prefix,hop)
	local number_ip = ipOps.todword(ip)
	if not number_ip then
		print("HOSTADDR:illege ip number:",ip,prefix)
		return
	end
	local begin_ip= bit.band(number_ip,(bit.lshift(0xffffffff,(32-prefix))))
	local number=bit.rshift(0xffffffff,prefix)
	--遍历ip/prefix内的全部目标，除去两端已探测的目标
	for i = begin_ip+2, begin_ip+number-2 do
		local now_ip=fastrace_fromdword(i)
		if VERBOSE >=1 then
			print("IMPROVE quicktrace_subnet:",number,now_ip,prefix,hop)
		end
		--快速探测hop的前后两跳
		local now_trace=quicktrace.quicktrace_main(now_ip,iface,VERBOSE,hop-2,hop+2)
		ALL_SEND_PACKET = ALL_SEND_PACKET + 3
		QUICKTRACE_SENT=QUICKTRACE_SENT+3
		if hop-2 >0 then
			QUICKTRACE_REDUNDANCE_COUNT=QUICKTRACE_REDUNDANCE_COUNT+hop-2
		end
		print_tr(now_trace,iface.address,OUTPUT_FILE_HANDLER,OUTPUT_TYPE)
		get_new_link_node_number(now_trace,prefix)
	end
end
--子网探测核心函数
--将cidr网段不断划分成更小网段，对网段两端目标进行正向反向探测，划分网段直到max_prefix_len,设置为31，覆盖全部目标

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
	local new_link,new_node
	local newsr = {}
	local oldsr = {}
	newsr['trace']={}
	oldsr['trace']={}
	if cidr['pfx']>=31 then
		if (cidr['pfx'] ~=32) and (HOSTADDR(cidr['net'],cidr['pfx'])==0) then
			cidr['net']=IP_INC(NETADDR(cidr['net'],cidr['pfx']))
		end
		if VERBOSE >= 1 then
			io.write("ARRIVE MAX_PREFIX_LEN,begin normal_traceroute"," prefix: ",cidr['pfx']," MAX_PREFIX_LEN: ",MAX_PREFIX_LEN,"\n")
		end
		normal_traceroute(cidr['net'])
		return
	end
	newsr['pfx']=cidr['pfx']
	--get first ip of subnet
	newsr['trace']['dst']=IP_INC(NETADDR(cidr['net'],cidr['pfx']))
	newsr['trace']['start'] = 1
	newsr['trace']['BNP']=-1
	newsr['trace']['cmp_ip']=0
	-- print(newsr['trace']['dst'],newsr['trace']['start'])
	if VERBOSE >= 1 then
		io.write("Fastrace ",newsr['trace']['dst'],"/",newsr['pfx']," at ",os.date("%Y-%m-%d %H:%M:%S"),"\n")
	end
	--1.1.1.1/20
	--首先对网段内第一个目标正常traceroute,后续才能以此目标作为参考进行正向反向探测
	if forward_traceroute(newsr['trace'],nil)==-1 then
		newsr=nil
		io.write("Fastrace STOP IN treetrace->forward_traceroute \n")
		return
	end
	ALL_TARGET=ALL_TARGET+1
	--统计对目标探测，是否发现新边，节点
	new_link , new_node = get_new_link_node_number(newsr['trace'],newsr['pfx'])
	if new_link > 0 or new_node >0 then
		newsr['find_new'] = 1
	else
		newsr['find_new'] =0 
	end
	--创建栈，将已探测第一个目标及当前前缀压栈
	local s = Stack:new()
	s:push(newsr)
	while s:is_empty() == false do
		ALL_TARGET=ALL_TARGET+1
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
		--如果栈顶时子网第一个元素，取出子网最后一个元素
		if HOSTADDR(oldsr['trace']['dst'],oldsr['pfx'])  == 1 then
			--取子网最后一个元素
			newsr['trace']['dst'] = IP_DEC(NETADDR(oldsr['trace']['dst'],oldsr['pfx']) + bit.rshift(0xffffffff,oldsr['pfx']))
			if VERBOSE >= 1 then
				io.write("|--",oldsr['trace']['dst'],"/",oldsr['pfx'],"-------the first ip on stack top\n")
				io.write("|--",newsr['trace']['dst'],"/",oldsr['pfx'],"-------get last  ip of subnet\n")
			end
		else
			--如果栈顶时子网最后一个元素，取出子网第一个元素
			newsr['trace']['dst'] = IP_INC(NETADDR(oldsr['trace']['dst'],oldsr['pfx']))
			if VERBOSE >= 1 then
				io.write("|--",newsr['trace']['dst'],"/",oldsr['pfx'],"-------get first ip of subnet\n")
				io.write("|--",oldsr['trace']['dst'],"/",oldsr['pfx'],"-------the last  ip on stack top\n")
			end
		end
		newsr['trace']['start'] = 0			--/* `start' waiting to be set by `oldsr'. */
		if VERBOSE >= 1 then 
			-- io.write('get oldsr on top stack:',oldsr['trace']['dst'],"/",oldsr['pfx'],"\n")
			-- io.write('get newsr by oldsr:',newsr['trace']['dst'],"/",oldsr['pfx'],"\n")
			io.write("Fastrace ",newsr['trace']['dst'],"/",oldsr['pfx']," at ",os.date("%Y-%m-%d %H:%M:%S"),"\n")
		end
		newsr['trace']['BNP']=-1
		newsr['trace']['cmp_ip']=oldsr['trace']['dst']
		--以栈顶参考目标，进行正向反向探测
		if forward_reverse(newsr['trace'],oldsr['trace'],oldsr['trace']) == -1 then
			s:clear()
			io.write("Fastrace STOP IN treetrace->forward_reverse \n")
			return
		end
		--获取目标发现的新边，节点数量
		new_link , new_node = get_new_link_node_number(newsr['trace'],oldsr['pfx'])
		if new_link > 0 or new_node >0 then
			newsr['find_new'] = 1
		else
			newsr['find_new'] = 0
		end
		--对于反向探测停止时，拷贝参考路径从第1跳到反向停止跳的路由器接口信息，作为目标的探测结果
		copy_tracehop(newsr['trace'],oldsr['trace'],1,newsr['trace']['start']-1)
		if newsr['trace']['rst'] == TR_RESULT_LOOP or newsr['trace']['rst'] ==TR_RESULT_MAXHOP then
			search_loop(newsr['trace'])
		end
		--IMPROVE:对新发现的最后几个新发现的节点也trace,但必须在copy_tracehop之后
		-- last_n_hop_is_new(newsr['trace'])
		--比较末跳路由，如果一致，则认为在同一子网，并且前缀大于MIN_PREFIX_LEN时，弹栈，终止对当前网段探测
		if compare_endrouter(newsr['trace'],oldsr['trace']) == 0 and oldsr['pfx'] >= MIN_PREFIX_LEN then
			s:pop()
			SAME_SUBNET_COUNT=SAME_SUBNET_COUNT+1
			if VERBOSE >= 1 then
				io.write("SAME SUBNET: new ip has same last hop with old ip,pop()",fastrace_fromdword(NETADDR(oldsr['trace']['dst'],oldsr['pfx'])),"/",oldsr['pfx'],"\n")
				io.write(oldsr['trace']['dst']," last hop: ",oldsr['trace']['hop'][oldsr['trace']['end'] - 1],"\n")
				io.write(newsr['trace']['dst']," last hop: ",newsr['trace']['hop'][newsr['trace']['end'] - 1],"\n")
				io.write("|--",oldsr['trace']['dst'],"/",oldsr['pfx'],"----the subnet\n")
				io.write("|--",oldsr['trace']['dst'],"-------the first ip of subnet\n")
				io.write("|--",newsr['trace']['dst'],"-------get last  ip of subnet\n")
				-- io.write("|--",oldsr['trace']['dst'],"/",oldsr['pfx'],"----the old ip pop()\n")
				-- io.write("|--",newsr['trace']['dst'],"-------the another ip of the subnet","\n")
			end
			print_tr(oldsr['trace'],iface.address,OUTPUT_FILE_HANDLER,OUTPUT_TYPE)
			print_tr(newsr['trace'],iface.address,OUTPUT_FILE_HANDLER,OUTPUT_TYPE)
			--IMPROVE:弹出时，对子网中间ip进行quicktrace，弃用，没有理论依据
			-- if IMPROVE >=1 then
			-- 	if VERBOSE >= 1 then 
			-- 		io.write("IMPROVE compare_endrouter\n")
			-- 	end
			-- 	quicktrace_subnet(oldsr['trace']['dst'],oldsr['pfx'],oldsr['trace']['end'])
			-- end
			oldsr={}
			newsr={}
			goto TREETRACE_WHILE
		end
		--Min non-new netmark prefix lenth. 
		--当前网段两端目标均未发现新边，节点，且前缀大于MIN_NO_NEW_PREFIX时，弹栈，终止对当前网段探测
		if newsr['find_new'] == 0 and oldsr['find_new'] == 0 and oldsr['pfx'] >= MIN_NO_NEW_PREFIX then
			s:pop()
			NO_NEW_LINK_NODE_COUNT=NO_NEW_LINK_NODE_COUNT+1
			if VERBOSE >= 1 then
				print("SUBNET No new links found pop(), subnet:")
				io.write("|--",oldsr['trace']['dst'],"/",oldsr['pfx'],"----the subnet\n")
				io.write("|--",oldsr['trace']['dst'],"-------the first ip of subnet\n")
				io.write("|--",newsr['trace']['dst'],"-------get last  ip of subnet\n")
				-- io.write("|",fastrace_fromdword(NETADDR(oldsr['trace']['dst'],oldsr['pfx'])),"/",oldsr['pfx'],"\n")
				-- io.write("|--",fastrace_fromdword(NETADDR(oldsr['trace']['dst'],oldsr['pfx']+1)),"/",oldsr['pfx']+1,"\n")
				-- io.write("|--",fastrace_fromdword(NETADDR(newsr['trace']['dst'],oldsr['pfx']+1)),"/",oldsr['pfx']+1,"\n")
			end
			print_tr(oldsr['trace'],iface.address,OUTPUT_FILE_HANDLER,OUTPUT_TYPE)
			print_tr(newsr['trace'],iface.address,OUTPUT_FILE_HANDLER,OUTPUT_TYPE)
			--对网段内目标进行quicktrace_subnet，无理论依据，弃用
			-- if IMPROVE >=1 then
			-- 	if VERBOSE >= 1 then 
			-- 		io.write("IMPROVE No new links found, pfx,min_no_new_prefix: ",oldsr['pfx']," ",MIN_NO_NEW_PREFIX,"\n")
			-- 	end
			-- 	quicktrace_subnet(oldsr['trace']['dst'],oldsr['pfx'],oldsr['trace']['end'])
			-- end
			oldsr={}
			newsr={}
			goto TREETRACE_WHILE
		end
		--当前网段前缀到达最大停止前缀MAX_PREFIX_LEN，停止探测，MAX_PREFIX_LEN=31，覆盖全部目标（当然MIN_NO_NEW_PREFIX，MIN_PREFIX_LEN也要设未31）
		if (oldsr['pfx']) >= MAX_PREFIX_LEN then
			s:pop()
			if VERBOSE >= 1 then
				print("SUBNET arrive max prefix lenth,pop()\n")
				io.write("|--",oldsr['trace']['dst'],"/",oldsr['pfx'],"----the subnet\n")
				io.write("|--",oldsr['trace']['dst'],"-------the first ip of subnet\n")
				io.write("|--",newsr['trace']['dst'],"-------get last  ip of subnet\n")
			end
			print_tr(oldsr['trace'],iface.address,OUTPUT_FILE_HANDLER,OUTPUT_TYPE)
			--TODO:last_hop_test
			-- if VERBOSE >= 1 then
			-- 	print("SUBNET arrive max prefix lenth,pop():",fastrace_fromdword(NETADDR(newsr['trace']['dst'],oldsr['pfx']+1)),oldsr['pfx']+1)
			-- end
			print_tr(newsr['trace'],iface.address,OUTPUT_FILE_HANDLER,OUTPUT_TYPE)
			--将该网段弹出时，对网段内目标进行quicktrace_subnet，无理论依据，弃用
			-- if IMPROVE >=1 then
			-- 	if VERBOSE >= 1 then 
			-- 		io.write("IMPROVE arrive MAX_PREFIX_LEN, pfx,MAX_PREFIX_LEN: ",oldsr['pfx']," ",MAX_PREFIX_LEN,"\n")
			-- 	end
			-- 	quicktrace_subnet(oldsr['trace']['dst'],oldsr['pfx'],oldsr['trace']['end'])
			-- end
			oldsr={}
			newsr={}
			goto TREETRACE_WHILE
		end
		--不符合弹栈条件，将当前网段前缀pfx加1，意思是分为两个子网段，为了进一步对两个子网段两端目标进行正向反向探测
		oldsr['pfx']=oldsr['pfx']+1
		newsr['pfx']=oldsr['pfx']
		s:push(newsr)
		if VERBOSE >= 1 then
			io.write("Tree continue to expand","\n")
			io.write("                  	|---",oldsr['trace']['dst'],"/",oldsr['pfx'],"-----this on top of stack\n")
			io.write("|",fastrace_fromdword(NETADDR(oldsr['trace']['dst'],oldsr['pfx']-1)),"/",oldsr['pfx']-1,"----\n")
			
			io.write("                  	|---",newsr['trace']['dst'],"/",newsr['pfx'],"-----this will push to stack\n")

			io.write("Stack PUSH ",newsr['trace']['dst'],"/",newsr['pfx'],"\n")
		end
		::TREETRACE_WHILE::
	end --end for while
	s:clear()
end
--末跳探测模块入口，参数：目标ip，网卡接口，result为了当前函数执行完，发送信号，
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
local function print_help()
	local print_text= 'Usage:  nmap --script fastrace.lua  --script-args="[[OPTION]=x,...]"  -e [INTERFACE]\n'
	..'OPTION is:\n'
	..'type .  .  .  .  .  .  .  .  . probe types (quicktrace/lastnhop/lasthop/help),def: traceroute\n' 
	..'ip .  .  .  .  . .  .  .  .  . ip,dot format/cidr format,eg. 1.1.1.1 or 1.1.1.1/24\n'	
	..'ip_list .  .  .  .  .  . .  .  ip list file path you input\n'	
	..'packet_type .  .  .  .  .  .  .probing packet types (MIX/TCP/UDP/ICMP), def: MIX \n'						
	..'max_timeout_per_hop .  .  .  . max timeout number for one hop, def: 2 \n'	
	..'max_continue_timeout_hops . .  max continue timeout hops, def: 3 \n'	
	..'max_prefix_len .  .  .  .  . . max prefix lenth, def: 30\n'	
	..'min_prefix_len .  .  .  .  .  .min prefix lenth, def: 20\n'	
	..'min_no_new_prefix .  .  .  . . min no-new-found prefix lenth, def: 24\n'	
	..'hops .  .  .  .  .  .  .  .  . for type=lastnhop, get last hops number middle router, def: 3\n'
	..'verbose .  .  .  .  .  .  .  . verbose output level (0/1/2/3), def: 0\n'	
	..'INTERFACE is your interface name\n'
	io.write(print_text)
end

action=function(host)
	--记录执行时间
	local start_time=os.time()
	print("__________________")
	-- print(MID_IP("1.1.1.1",29))
	--获取网卡接口信息，使用-sn -n 8.8.8.8可以默认选择外网网卡
	local ifname = nmap.get_interface() or host.interface
	if not ifname then
		return fail("Failed to determine the network interface name")
	end
	-- print(ifname)
	local prober_type=stdnse.get_script_args("type")	--默认traceroute
	if prober_type == "help" then 
		print_help()
		return 0
	end
	iface = nmap.get_interface_info(ifname)
	send_l3_sock = nmap.new_dnet()
	send_l3_sock:ip_open()
	--从参数里读入目标或目标文件
	local dst_ip=stdnse.get_script_args("ip")
	local ip_file=stdnse.get_script_args("ip_file")
	if (not dst_ip)  and (not ip_file) then
		return fail("error:no target input")
	end
	if (dst_ip)  and (ip_file) then
		return fail("error:muti target")
	end
	--选择子网探测时，使用的探测包类型，MIX/TCP/ICMP/UDP
	PACKET_TYPE=stdnse.get_script_args("packet_type")	--默认traceroute
	-- verbose=0
	VERBOSE=stdnse.get_script_args("verbose")								--输出调试信息等级
	MAX_TIMEOUT_PER_HOP=stdnse.get_script_args("max_timeout_per_hop")		--单跳最大重试次数
	MAX_TIMEOUT_HOPS=stdnse.get_script_args("max_continue_timeout_hops")	--最大连续超时跳数
	MAX_PREFIX_LEN=stdnse.get_script_args("max_prefix_len")					--treetrace最大探测子网前缀
	MIN_PREFIX_LEN=stdnse.get_script_args("min_prefix_len")					--treetrace停止探测最小子网前缀
	MIN_NO_NEW_PREFIX=stdnse.get_script_args("min_no_new_prefix")			--treetrace子网未发现新的节点或边时最小停止探测前缀

	VERBOSE=tonumber(VERBOSE)
	MAX_TIMEOUT_PER_HOP=tonumber(MAX_TIMEOUT_PER_HOP)						
	MAX_TIMEOUT_HOPS=tonumber(MAX_TIMEOUT_HOPS)
	MAX_PREFIX_LEN=tonumber(MAX_PREFIX_LEN)
	MIN_PREFIX_LEN=tonumber(MIN_PREFIX_LEN)
	MIN_NO_NEW_PREFIX=tonumber(MIN_NO_NEW_PREFIX)
	--结果输出文件
	OUTPUT_TYPE=stdnse.get_script_args("output_type")						--输出类型，output_type!=file,则只输出控制台
	OUTPUT_FILE_HANDLER=""
	-- print("IMPROVE",IMPROVE)
	-- print(OUTPUT_TYPE)
	--写入文件
	if OUTPUT_TYPE == "file" then
		OUTPUT_FILENAME=stdnse.get_script_args("output_filename")
		OUTPUT_FILE_HANDLER=io.open(OUTPUT_FILENAME,'w')
	end
	--是否使用改善方案，已弃用，
	IMPROVE=stdnse.get_script_args("improve")
	IMPROVE=tonumber(IMPROVE)
	DEBUG=0 		--已弃用
	-- print("verbose,debug:",VERBOSE,DEBUG)
	global_link_hashmap={}		--记录全局边信息
	global_node={}				--记录全局节点信息
	-- VERBOSE=1
	if prober_type == "quicktrace" then
		if dst_ip then
			local ip, err = ipOps.expand_ip(dst_ip)
			if not err then
				local trace=quicktrace.quicktrace_main(dst_ip,iface,VERBOSE,1,30)
			else
				return fail("error:illege ip")
			end
		elseif ip_file then 	--目标为文件
			for line in io.lines(ip_file) do
				dst_ip = line
				local ip, err = ipOps.expand_ip(dst_ip)
				if not err then
					local trace=quicktrace.quicktrace_main(dst_ip,iface,VERBOSE,1,30)
					trace['BNP']=0 --for print_tr in base.lua 
					trace['cmp_ip']=0
					get_new_link_node_number(trace,32)
					-- print_tr(trace,iface.address,OUTPUT_FILE_HANDLER,OUTPUT_TYPE)
				else
					fail("error:illege ip")
				end
			end
		else
			return fail("error:no target input")
		end
		io.write("ALL_LINK: ",ALL_LINK," ALL_NODE: ",ALL_NODE,"\n")
		return true
	end 
	--last_N_hop
	--探测倒数第n跳
	if prober_type == "lastnhop" then
		LAST_N_HOP_NUMBER=stdnse.get_script_args("hops")						--获取倒数多少跳
		LAST_N_HOP_NUMBER=tonumber(LAST_N_HOP_NUMBER)

		if dst_ip then
			local ip, err = ipOps.expand_ip(dst_ip)
			if not err then
				last_N_hop.last_n_hop_main(dst_ip,LAST_N_HOP_NUMBER,iface,VERBOSE)
			else
				return fail("error:illege ip")
			end
		elseif ip_file then 	--目标为文件
			for line in io.lines(ip_file) do
				dst_ip = line
				local ip, err = ipOps.expand_ip(dst_ip)
				if not err then
					last_N_hop.last_n_hop_main(dst_ip,last_hop_number,iface,VERBOSE)
				else
					fail("error:illege ip")
				end
			end
		else
			return fail("error:no target input")
		end
		return true
	end


	--末跳探测
	if prober_type =='last_hop' then
		if dst_ip then
			local ip, err = ipOps.expand_ip(dst_ip)
			if not err then
				-- local test={}
				-- test[1]="asfd"
				last_hop_main(dst_ip,iface)
				print(test[1])
			else
				print("error:illege ip",dst_ip)
				return true
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

	--不指定探测类型type，默认traceroute或子网发现
	if dst_ip then
		local cidr = str2cidr(dst_ip)
		-- print(cidr['net'],cidr['pfx'])
		local temp, err = ipOps.expand_ip(cidr['net'])
		if err or dst_ip:match( ":" ) ~= nil then
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
		-- print_all_node_link()
		io.write("ALL_LINK: ",ALL_LINK," ALL_NODE: ",ALL_NODE,"\n")
	elseif ip_file then 	--目标为文件
		for line in io.lines(ip_file) do
			local ip=stdnse.strsplit(" ", line)
			local cidr = str2cidr(ip[1])
			-- print(cidr['net'],cidr['pfx'])
			local temp, err = ipOps.expand_ip(cidr['net'])
			if not err and line:match( ":" ) == nil then
				-- print(HOSTADDR(cidr['net'],cidr['pfx']))
				-- print(NETADDR(cidr['net'],cidr['pfx']))
				if cidr['pfx']>=32 then
					normal_traceroute(cidr['net'])
				elseif cidr['pfx'] >=1 then
					treetrace(cidr)
					print("global_link_hashmap,global_node",#global_link_hashmap,#global_node)
				else
					print("error cidr format:",ip[1],cidr['net'],cidr['pfx'])
				end
			else
				print("error:illege ip",cidr['net'])
			end
		end--end for
		-- print_all_node_link()
	else
	end
	local end_time=os.time()
	local RUNTIME=(end_time-start_time)/60
    if OUTPUT_TYPE == "file" then
    	for k,v in pairs(TEST_PFX_INFO) do
    		OUTPUT_FILE_HANDLER:write("TEST_PFX_INFO: ",k," ",v['link']," ",v['node']," ",v['router'],"\n")
    	end
		for k,v in pairs(MID_ROUTER_SEND) do
			OUTPUT_FILE_HANDLER:write("MID_ROUTER_SEND: ",k," ",v,"\n")
		end
    	for k,v in pairs(EVERY_TATGET_SEND) do
    		OUTPUT_FILE_HANDLER:write("EVERY_TATGET_SEND: ",k," ",v,"\n")
    	end
		OUTPUT_FILE_HANDLER:write("ALL_TARGET: ",ALL_TARGET,"\n")
    	OUTPUT_FILE_HANDLER:write("ALL_NODE: ",ALL_NODE,"\n")
    	OUTPUT_FILE_HANDLER:write("MID_ROUTER_COUNT: ",MID_ROUTER_COUNT,"\n")
		OUTPUT_FILE_HANDLER:write("TARGET_ARRIVE: ",TARGET_ARRIVE,"\n")

    	OUTPUT_FILE_HANDLER:write("ALL_LINK: ",ALL_LINK,"\n")
		OUTPUT_FILE_HANDLER:write("TO_TARGET_LINK: ",TO_TARGET_LINK,"\n")

		OUTPUT_FILE_HANDLER:write("MAX_TIMEOUT_PER_HOP: ",MAX_TIMEOUT_PER_HOP,"\n")
		OUTPUT_FILE_HANDLER:write("MAX_TIMEOUT_HOPS: ",MAX_TIMEOUT_HOPS,"\n")
		OUTPUT_FILE_HANDLER:write("MIN_PREFIX_LEN: ",MIN_PREFIX_LEN,"\n")
		OUTPUT_FILE_HANDLER:write("MAX_PREFIX_LEN: ",MAX_PREFIX_LEN,"\n")
		OUTPUT_FILE_HANDLER:write("MIN_NO_NEW_PREFIX: ",MIN_NO_NEW_PREFIX,"\n")

		OUTPUT_FILE_HANDLER:write("ALL_SEND_PACKET: ",ALL_SEND_PACKET,"\n")
		OUTPUT_FILE_HANDLER:write("QUICKTRACE_SENT: ",QUICKTRACE_SENT,"\n")
		OUTPUT_FILE_HANDLER:write("HOPPING_SEND: ",ALL_SEND_PACKET-QUICKTRACE_SENT,"\n")

		OUTPUT_FILE_HANDLER:write("BNP_REDUNDANCE_COUNT: ",BNP_REDUNDANCE_COUNT,"\n")
		OUTPUT_FILE_HANDLER:write("QUICKTRACE_REDUNDANCE_COUNT: ",QUICKTRACE_REDUNDANCE_COUNT,"\n")
		OUTPUT_FILE_HANDLER:write("SAME_SUBNET_COUNT: ",SAME_SUBNET_COUNT,"\n")
		OUTPUT_FILE_HANDLER:write("NO_NEW_LINK_NODE_COUNT: ",NO_NEW_LINK_NODE_COUNT,"\n")

		OUTPUT_FILE_HANDLER:write("BNP_COUNT: ",BNP_COUNT,"\n")
		OUTPUT_FILE_HANDLER:write("NNS_COUNT: ",NNS_COUNT,"\n")
		OUTPUT_FILE_HANDLER:write("RUNTIME: ",RUNTIME,"\n")
	end

	for k,v in pairs(TEST_PFX_INFO) do
		
		io.write("TEST_PFX_INFO: ",k," ",v['link']," ",v['node']," ",v['router'],"\n")
	end
	for k,v in pairs(MID_ROUTER_SEND) do
		print("MID_ROUTER_SEND: ",k,v)
	end
	for k,v in pairs(EVERY_TATGET_SEND) do
		print("EVERY_TATGET_SEND: ",k,v)
	end
	print("ALL_TARGET: ",ALL_TARGET)
	print("ALL_NODE: ",ALL_NODE)
	print("MID_ROUTER_COUNT: ",MID_ROUTER_COUNT)
	print("TARGET_ARRIVE: ",TARGET_ARRIVE)
	print("ALL_LINK: ",ALL_LINK)
	print("TO_TARGET_LINK: ",TO_TARGET_LINK)

	print("ALL_SEND_PACKET: ",ALL_SEND_PACKET)
	print("QUICKTRACE_SENT: ",QUICKTRACE_SENT)
	print("HOPPING_SEND: ",ALL_SEND_PACKET-QUICKTRACE_SENT)

	print("BNP_REDUNDANCE_COUNT: ",BNP_REDUNDANCE_COUNT)
	print("QUICKTRACE_REDUNDANCE_COUNT: ",QUICKTRACE_REDUNDANCE_COUNT)
	print("SAME_SUBNET_COUNT: ",SAME_SUBNET_COUNT)
	print("NO_NEW_LINK_NODE_COUNT: ",NO_NEW_LINK_NODE_COUNT)
	print("BNP_COUNT: ",BNP_COUNT)
	print("NNS_COUNT: ",NNS_COUNT)
	print("RUNTIME: ",RUNTIME)
	-- local s = Stack:new()
	-- s:push(1)
	-- s:push(2)
	-- print(s:top())
	-- s:printElement()
	send_l3_sock:ip_close()
	if OUTPUT_TYPE == "file" then
		OUTPUT_FILE_HANDLER:close()
	end
	return true
end