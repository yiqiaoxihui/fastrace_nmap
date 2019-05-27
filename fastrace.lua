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
-- local datetime = require "datetime"
-- local io = require "io"
require('base')
require('prober')
require('last_hop')
require('unit_test')
local quicktrace = require('quicktrace')
local last_N_hop = require('last_N_hop')
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
	ALL_SEND_PACKET=ALL_SEND_PACKET+1
	local pi={}		--探测信息
	-- print(try)
	local send_packet_type=PROBING_TYPE_ARRAY[try]
	--探测类型参数
	if PACKET_TYPE == "ICMP" then
		send_packet_type=PPK_ICMPECHO
	elseif PACKET_TYPE == "UDP" then
		send_packet_type=PPK_UDPBIGPORT
	elseif PACKET_TYPE == "TCP" then
		send_packet_type=PPK_SYN
	else
	end
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
		if rpk_type ==0 then
			return -1
		end
		if rpk_type == RPK_TIMEOUT then
			---print("*HOP:",ttl,"timeout:",timeout)
			trace['hop'][ttl]=0
			trace['rtt'][ttl]=0
			trace['reply_ttl'][ttl]=0
			-- ttl=ttl-1
			goto reverse_hopping_begin
		end
		trace['hop'][ttl] = from
		trace['rtt'][ttl]=rtt
		trace['reply_ttl'][ttl]=reply_ttl
		if rpk_type ~= RPK_TIMEEXC then
			if IS_UNREACH(rpk_type) == 1 then 		--0 and 1 for lua is true
				code=rpk_type - RPK_UNREACH
				if code ~= ICMP_PROT_UNREACH and code ~= ICMP_PORT_UNREACH then
					trace['rst'] = TR_RESULT_UNREACH
		        	if VERBOSE >= 1 then
		        		print("reverse_traceroute NOT_RPK_TIMEEXC IS_UNREACH TR_RESULT_UNREACH")
		        	end
				else
					---print(">HOP:",ttl,"get target:",from)
					trace['rst'] = TR_RESULT_GOTTHERE
		        	if VERBOSE >= 1 then
		        		print("reverse_traceroute ,NOT RPK_TIMEEXC ,IS_UNREACH ,ICMP_PROT_UNREACH or ICMP_PORT_UNREACH, TR_RESULT_GOTTHERE")
		        	end
				end
			else
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
        ---print(">HOP:",ttl,"from:",from)
        --错误的报文
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
        if cmptrace ~= nil and cmptrace['start'] <= ttl and cmptrace['end'] >= ttl and cmptrace['hop'][ttl] == trace['hop'][ttl] then
        	trace['start'] = ttl
			if trace['rst'] == 0 then		--仅当没有TR_RESULT_GOTTHERE和TR_RESULT_FAKE
				---print("TR_RESULT_DESIGN:",ttl,"from:",from)
				trace['rst'] = TR_RESULT_DESIGN
			end
			if VERBOSE >= 1 then
				io.write("reverse_traceroute BNP, ","current ip has same hop with cmptrace on ttl = ",ttl," return\n")
			end
			return 1
		end
		::reverse_hopping_begin::
		ttl=ttl-1
	end
	if VERBOSE >= 1 then
		io.write("reverse_traceroute ttl arrive 1, return\n")
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
	trace['rtt']={}
	trace['reply_ttl']={}
	---print("forward_traceroute:")
	while ttl <= MAX_HOP do
		-- print("begin:",timeout,timeout_hops)
		if timeout >=1 or timeout_hops>=1 then
			try=GET_TRY(try)
		end
		-- print("begin hopping:",rpk_type,from)
		rpk_type,from,rtt,reply_ttl=hopping(trace['dst'],ttl,try)
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
					trace['rtt'][ttl]=0
					trace['reply_ttl'][ttl]=0

					trace['end']=ttl
					trace['rst']=TR_RESULT_TIMEOUT
					if VERBOSE >= 1 then
						io.write("forward_traceroute NNS by cmptrace, cmptrace stop on this ttl timeout, and this ip ",trace['dst']," timeout as well as cmptrace on this ttl= ",ttl,", NNS stop.\n")
					end
					return 1
				end
			end

			if timeout==MAX_TIMEOUT_PER_HOP then	--一跳上连续 MAX_TIMEOUT_PER_HOP 次超时
				timeout=0
				timeout_hops=timeout_hops+1
				trace['hop'][ttl]=0
				trace['rtt'][ttl]=0
				trace['reply_ttl'][ttl]=0
				if timeout_hops>=MAX_TIMEOUT_HOPS then	--连续MAX_TIMEOUT_HOPS跳超时，退出，否则进行下一跳
					--Too many continuous timeout.
					--Remain a router ZERO at the end of path.
					trace['end']=ttl - MAX_TIMEOUT_HOPS+1
					trace['rst']=TR_RESULT_TIMEOUT
					if timeouth>=1 then
						print("TOH OK")
					end
					if VERBOSE >= 1 then
						io.write("forward_traceroute TR_RESULT_TIMEOUT, ttl:",ttl,"no result ON continue ",timeout_hops,"hops, stop.\n")
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
		trace['rtt'][ttl]=rtt
		trace['reply_ttl'][ttl]=reply_ttl
		if rpk_type == RPK_TIMEEXC then
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
			--不是端口不可达和协议不可达的，都停止探测，why 协议不可达也可以继续
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
	if trace['rst'] ~= TR_RESULT_DESIGN then 			--原因能是：在 reverse_traceroute 中到达目标 TR_RESULT_GOTTHERE
		if VERBOSE >=1 then
			io.write('forward_reverse, arrive target in reverse_traceroute,real end: ',trace['end']," before end: ",fend,"\n")
		end
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
local function get_new_link_node_number(trace)
	local new_link = 0
	local new_node = 0
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
			if global_link_hashmap[link_key] == nil then
				ALL_LINK=ALL_LINK+1
				new_link= new_link + 1
				global_link_hashmap[link_key] = 1
				if DEBUG == 1 or VERBOSE>=2 then
					io.write('new link:',trace['hop'][i],' ~~~~~~~~~~~~~~~~ ',trace['hop'][i+1],"\n")
				end
				-- return 1
			end
		end
		if trace['hop'][i] ~= 0 and global_node[trace['hop'][i]] == nil then
			
			new_node = new_node + 1
			ALL_NODE = ALL_NODE +1
			global_node[trace['hop'][i]] = 1
			if DEBUG == 1 or VERBOSE >=2 then
				io.write('new node:',trace['hop'][i],"\n")
			end

			-- return 1
		end
	end
	if DEBUG == 1 or VERBOSE>=1 then
		print("***********find new link, node************",new_link,new_node)
	end
	return new_link,new_node
end
local function last_n_hop_is_new(trace)
	io.write("IMPROVE last_n_hop_is_new\n")
	for i=(trace['end']-1)-2,trace['end']-1 do
		if trace['hop'][i] ~= nil and trace['hop'][i] ~= 0 and global_node[trace['hop'][i]] == nil then
			--IMPROVE:对新发现的最后几个新发现的节点也trace
			if  i < (trace['end']-1) and (trace['end']-1)-i <= 2 then
				if IMPROVE >=1 then
					if VERBOSE >= 1 then 
						-- io.write("IMPROVE last_n_hop_is_new, end: ",trace['end'],"hop ",i," :","\n")
						io.write("IMPROVE last_n_hop_is_new, end: ",trace['end'],"hop ",i," :",trace['hop'][i],"\n")
					end
					local qtrace=quicktrace.quicktrace_main(trace['hop'][i],iface,VERBOSE)
					get_new_link_node_number(qtrace)		--再次统计新节点和边
					print_tr(qtrace,iface.address,OUTPUT_FILE_HANDLER,OUTPUT_TYPE)
				end
			end
			ALL_NODE = ALL_NODE +1
			global_node[trace['hop'][i]] = 1
			-- return 1
		end
	end
end
local function normal_traceroute(dst_ip)
	local trace={}
	trace['dst']=dst_ip
	trace['start']=1
	if VERBOSE >= 1 then
		io.write("Fastrace ",dst_ip,"/32"," at ",os.date("%Y-%m-%d %H:%M:%S"),"\n")
	end
	forward_traceroute(trace,nil)
	get_new_link_node_number(trace) 		--更新已获取边，节点
	print_tr(trace,iface.address,OUTPUT_FILE_HANDLER,OUTPUT_TYPE)
end
local function copy_tracehop(tracedst,tracesrc,ttls,ttle)
	--copy from reverse_traceroute
	for i=ttls,ttle do
		tracedst['hop'][i] = tracesrc['hop'][i]
		tracedst['rtt'][i]=tracesrc['rtt'][i]
		tracedst['reply_ttl'][i]=tracesrc['reply_ttl'][i]
		REDUNDANCE_COUNT=REDUNDANCE_COUNT+1
	end
	tracedst['start']=ttls
end
local function compare_endrouter(trace1,trace2)
	if trace1['rst'] == TR_RESULT_DESIGN or trace2['rst'] == TR_RESULT_DESIGN then
		return -1
	end
	if trace1['end'] <= 2 then
		return 1 			--IMPROVE:少于2跳的，认为未到达目标，继续探测
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
local function quicktrace_subnet(ip,prefix,hop)
	local number_ip = ipOps.todword(ip)
	if not number_ip then
		print("HOSTADDR:illege ip number:",ip,prefix)
		return
	end
	local begin_ip= bit.band(number_ip,(bit.lshift(0xffffffff,(32-prefix))))
	local number=bit.rshift(0xffffffff,prefix)
	if begin_ip+2 > begin_ip+number-1 then 
		return
	end
	for i = begin_ip+2, begin_ip+number-1 do
		local now_ip=fastrace_fromdword(i)
		if VERBOSE >=1 then
			print("IMPROVE quicktrace_subnet:",now_ip,hop-2,hop+2)
		end
		local now_trace=quicktrace.quicktrace_main(now_ip,iface,VERBOSE,hop-2,hop+2)
		get_new_link_node_number(now_trace)
	end
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
	local new_link,new_node
	local newsr = {}
	local oldsr = {}
	newsr['trace']={}
	oldsr['trace']={}
	if cidr['pfx']>=MAX_PREFIX_LEN then
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
	newsr['trace']['dst']=IP_INC(NETADDR(cidr['net'],cidr['pfx']))
	newsr['trace']['start'] = 1
	-- print(newsr['trace']['dst'],newsr['trace']['start'])
	if VERBOSE >= 1 then
		io.write("Fastrace ",newsr['trace']['dst'],"/",newsr['pfx']," at ",os.date("%Y-%m-%d %H:%M:%S"),"\n")
	end
	if forward_traceroute(newsr['trace'],nil)==-1 then
		newsr=nil
		return
	end
	new_link , new_node = get_new_link_node_number(newsr['trace'])
	if new_link > 0 or new_node >0 then
		newsr['find_new'] = 1
	else
		newsr['find_new'] =0 
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
			if VERBOSE >= 1 then
				io.write("|--",oldsr['trace']['dst'],"/",oldsr['pfx'],"-------the first ip on stack top\n")
				io.write("|--",newsr['trace']['dst'],"/",oldsr['pfx'],"-------get last  ip of subnet\n")
			end
		else
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
		if forward_reverse(newsr['trace'],oldsr['trace'],oldsr['trace']) == -1 then
			s:clear()
			return
		end
		new_link , new_node = get_new_link_node_number(newsr['trace'])
		if new_link > 0 or new_node >0 then
			newsr['find_new'] = 1
		else
			newsr['find_new'] = 0
		end

		copy_tracehop(newsr['trace'],oldsr['trace'],1,newsr['trace']['start']-1)
		if newsr['trace']['rst'] == TR_RESULT_LOOP or newsr['trace']['rst'] ==TR_RESULT_MAXHOP then
			search_loop(newsr['trace'])
		end
		--IMPROVE:对新发现的最后几个新发现的节点也trace,但必须在copy_tracehop之后
		last_n_hop_is_new(newsr['trace'])
		--比较末跳路由，如果一致，则认为在同一子网
		if compare_endrouter(newsr['trace'],oldsr['trace']) == 0 and oldsr['pfx'] >= MIN_PREFIX_LEN then
			s:pop()
			--IMPROVE:弹出时，对子网中间ip进行quicktrace
			if IMPROVE >=1 then
				if VERBOSE >= 1 then 
					io.write("IMPROVE compare_endrouter\n")
				end
				quicktrace_subnet(oldsr['trace']['dst'],oldsr['pfx'],oldsr['trace']['end'])
				-- local trace=quicktrace.quicktrace_main(MID_IP(oldsr['trace']['dst'],oldsr['pfx']),iface,VERBOSE)
				-- get_new_link_node_number(trace)
				-- print_tr(trace,iface.address,OUTPUT_FILE_HANDLER,OUTPUT_TYPE)
			end
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
			oldsr={}
			newsr={}
			goto TREETRACE_WHILE
		end
		--Min non-new netmark prefix lenth. 
		if newsr['find_new'] == 0 and oldsr['find_new'] == 0 and oldsr['pfx'] >= MIN_NO_NEW_PREFIX then
			s:pop()
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
			oldsr={}
			newsr={}
			goto TREETRACE_WHILE
		end
		if (oldsr['pfx'] + 1) >= MAX_PREFIX_LEN then
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
			oldsr={}
			newsr={}
			goto TREETRACE_WHILE
		end
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
action=function()
	print("__________________")
	-- print(MID_IP("1.1.1.1",29))
	local ifname = nmap.get_interface() or host.interface
	if not ifname then
		return fail("Failed to determine the network interface name")
	end
	local prober_type=stdnse.get_script_args("type")	--默认traceroute
	if prober_type == "help" then 
		print_help()
		return 0
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
	

	PACKET_TYPE=stdnse.get_script_args("packet_type")	--默认traceroute
	-- verbose=0
	VERBOSE=stdnse.get_script_args("verbose")								--调试信息等级
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
	OUTPUT_TYPE=stdnse.get_script_args("output_type")
	OUTPUT_FILE_HANDLER=""
	-- print("IMPROVE",IMPROVE)
	-- print(OUTPUT_TYPE)
	if OUTPUT_TYPE == "file" then
		OUTPUT_FILENAME=stdnse.get_script_args("output_filename")
		OUTPUT_FILE_HANDLER=io.open(OUTPUT_FILENAME,'w')
	end
	--是否使用改善方案
	IMPROVE=stdnse.get_script_args("improve")
	IMPROVE=tonumber(IMPROVE)
	DEBUG=0
	-- print("verbose,debug:",VERBOSE,DEBUG)
	global_link_hashmap={}
	global_node={}
	-- VERBOSE=1
	if prober_type == "quicktrace" then
		if dst_ip then
			local ip, err = ipOps.expand_ip(dst_ip)
			if not err then
				local trace=quicktrace.quicktrace_main(dst_ip,iface,VERBOSE,1,30)
				print_tr(trace,iface.address,OUTPUT_FILE_HANDLER,OUTPUT_TYPE)
			else
				return fail("error:illege ip")
			end
		else
			return fail("error:no target input")
		end
		return true
	end 
	--last_N_hop
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
	if prober_type =='last_hop' then
		if dst_ip then
			local ip, err = ipOps.expand_ip(dst_ip)
			if not err then
				last_hop_main(dst_ip,iface)
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
		print_all_node_link()
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
		print_all_node_link()
		io.write("ALL_LINK: ",ALL_LINK," ALL_NODE: ",ALL_NODE,"\n")
	else
	end
	print("ALL_SEND_PACKET:",ALL_SEND_PACKET)
	print("REDUNDANCE_COUNT:",REDUNDANCE_COUNT)
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