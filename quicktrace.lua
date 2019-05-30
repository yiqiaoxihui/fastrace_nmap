local bin = require "bin"
local coroutine = require "coroutine"
local ipOps = require "ipOps"
local math = require "math"
local nmap = require "nmap"
local packet = require "packet"
local stdnse = require "stdnse"
local string = require "string"

quicktrace={}

--1. l3 packet table中没有echo_id,使用l3_rpk_packet:u16(l3_rpk_packet.icmp_offset + 4)获取
--2.忘记加括号导致过滤器无法获取echo reply
function quicktrace_icmp_reply_listener(dst_ip,trace,send_l3_sock,icmp_reply_listener_signal,device,VERBOSE)
	local rpk_type			--返回包类型
	local from 				--返回包ip
	local rtt 				--往返时延
	local reply_ttl 		--回包中ttl
	local send_ttl			--探测包发送的ttl
	local end_time
	local echo_id
	local icmp_type
	local icmp_code
	local condvar = nmap.condvar(icmp_reply_listener_signal)
	local str_hex_ip=ipOps.todword(dst_ip)
	-- print(echo_seq,echo_id)
	local icmp_rec_socket=nmap.new_socket()
	--来自目标返回的ping reply 
	local capture_rule_echo_reply="(icmp[0]=0 and icmp[1]=0 and src host "..dst_ip..")"
	--icmp[0]="..ICMP_TIME_EXCEEDED.." and icmp[1]="..ICMP_EXC_TTL.." and 
	local capture_rule_icmp_error="((icmp[0]=11) and (icmp[1]=0) and icmp[24:4]="..str_hex_ip..")"--忘记加括号导致过滤器无法获取echo reply
	local capture_rule_icmp=capture_rule_echo_reply.." or "..capture_rule_icmp_error
	icmp_rec_socket:pcap_open(device,128,false,capture_rule_icmp)
	icmp_rec_socket:set_timeout(2000)
 
	while icmp_reply_listener_signal['status'] == 0 do
		local status,len,l2_icmp,l3_icmp,time=icmp_rec_socket:pcap_receive()
		if status then
			echo_id= nil
			end_time=stdnse.clock_ms()
			-- print("get icmp packet back")
			local l3_rpk_packet = packet.Packet:new(l3_icmp, #l3_icmp)
			if #l3_icmp<(IP_HEAD_SIZE+ICMP_HEAD_SIZE) then
				if VERBOSE >= 1 then
					print("!BROKEN PACKET:ICMP_PACKET","l3_len:",#l3_icmp,"from",l3_rpk_packet['src_ip'])
				end
				--return 0
			end
			-- for k,v in pairs(l3_rpk_packet) do
			-- 	print("l3_rpk_packet:",k,v)
			-- end
			reply_ttl=l3_rpk_packet.ip_ttl
			from=l3_rpk_packet['ip_src']
			icmp_type=l3_rpk_packet['icmp_type']
			icmp_code=l3_rpk_packet['icmp_code']
			--ping reply
			if icmp_type == 0 and icmp_code ==0 then
				--echo_id=l3_rpk_packet['echo_id']
				echo_id=l3_rpk_packet:u16(l3_rpk_packet.icmp_offset + 4)
				if VERBOSE >= 2 then
					print("RPK_ICMPECHO",echo_id)
				end
				if echo_id ~= nil and trace['echo_id'][echo_id] ~= nil then
					send_ttl = trace['echo_id'][echo_id]
					if trace['end'] > send_ttl then
						trace['end'] = send_ttl
					end
					trace['hop'][send_ttl]['reply_ttl']=reply_ttl
					trace['hop'][send_ttl]['from']=from
					trace['hop'][send_ttl]['rtt']=end_time - trace['rtt'][send_ttl]['start_time']
				else
					if VERBOSE >= 1 then
						print("not find echo_id in trace table:",echo_id)
					end
				end

			end
			if icmp_type == 11 and icmp_code == 0 then
				if (#l3_icmp-l3_rpk_packet['icmp_payload_offset'])<(IP_HEAD_SIZE+ICMP_HEAD_SIZE) then
					if VERBOSE >= 1 then
						print("!BROKEN PACKET:ICMP_DEST_UNREACH","l3_len:",l3_len,"from",l3_rpk_packet['src_ip'])
					end
				else
					local raw_sender_data_in_l3_rpk_packet=l3_icmp:sub(l3_rpk_packet.icmp_payload_offset+1)
					local raw_sender_packet=packet.Packet:new(raw_sender_data_in_l3_rpk_packet,#raw_sender_data_in_l3_rpk_packet)

					echo_id=raw_sender_packet:u16(raw_sender_packet.icmp_offset + 4)
					--echo_id = raw_sender_packet['echo_id']
					if VERBOSE >= 2 then
						print("ICMP_EXC_TTL",echo_id)
					end
					if echo_id ~= nil and trace['echo_id'][echo_id] ~= nil then
						send_ttl = trace['echo_id'][echo_id]
						trace['hop'][send_ttl]['from']=from
						trace['hop'][send_ttl]['reply_ttl']=reply_ttl
						trace['hop'][send_ttl]['rtt']=end_time - trace['rtt'][send_ttl]['start_time']
					else
						if VERBOSE >= 1 then
							print("not find echo_id in trace table:",echo_id)
						end
					end
				end
			end

			-- for k,v in pairs(icmp_timeexc_packet) do
			-- 	print("ip:",k,v)
			-- end
			--rpk_type:PPK_ICMPECHO,RPK_ICMPECHO,RPK_UNREACH+code,RPK_TIMEEXC,0其他类型
			-- rpk_type=parsepack.get_ptype_icmp(l3_rpk_packet,#l3_icmp)
			-- print(">HOP:",pi['ttl'],from)
		else
			if VERBOSE >= 1 then
				print("icmp reply linstener timeout")
			end
		end
	end
	icmp_rec_socket:close()
	condvar("signal")
end

function set_ttl_to_ping(trace,ttl,echo_id,send_l3_sock,device)
	-- echo_seq=1
	local ip=packet.Packet:new()
	ip.ip_bin_dst = trace['ip_bin_dst']
	ip.ip_bin_src = trace['ip_bin_src']
	ip.echo_data = "abc"
	-- ip.echo_seq = echo_seq
	ip.echo_id=echo_id
	ip.ip_offset=0
	ip:build_icmp_echo_request()
	ip:build_icmp_header()
	ip:build_ip_packet()
	ip:ip_set_ttl(ttl)
	local start_time
	start_time=stdnse.clock_ms()
	trace['rtt'][ttl]={}
	trace['rtt'][ttl]['start_time']=start_time
	for k,v in pairs(ip) do
		--print("ip:",k,v)
	end
	send_l3_sock:ip_send(ip.buf)
end

function quicktrace.quicktrace_main(dst_ip,iface,VERBOSE,begin_hop,end_hop)
	--建立发送l3层报文的raw socket
	--用于发送设置了ttl的探测末跳报文
	-- print("quicktrace：",VERBOSE)
	local send_l3_sock = nmap.new_dnet()
	send_l3_sock:ip_open()

	local trace={}
	trace['ip_bin_src']=ipOps.ip_to_str(iface.address)
	trace['ip_bin_dst']=ipOps.ip_to_str(dst_ip)
	trace['hop']={}
	trace['echo_seq']={}
	trace['echo_id']={}
	trace['rtt']={}
	trace['start']=1
	trace['end']=30
	--建立监听线程,用于接受icmp端口不可达包
	--
	-- @param icmp_pu_listener function name
	-- @param send_l3_sock l3 layer raw socket
	-- @param icmp_pu_listener_signal listener stop signal
	local icmp_reply_listener_signal={}
	local icmp_reply_listener_condvar = nmap.condvar(icmp_reply_listener_signal)
	icmp_reply_listener_signal['status']=0 	--监听结束信号
	icmp_reply_listener_signal['icmp_pu']=0 	--是否收到icmp端口不可达信号
	local icmp_reply_listener_handler=stdnse.new_thread(quicktrace_icmp_reply_listener,dst_ip,trace,send_l3_sock,icmp_reply_listener_signal,iface.device,VERBOSE)
	stdnse.sleep(1)

	local echo_seq
	local echo_id
	for i=1,30 do
		echo_id=math.random(0x0, 0xffff)
		while trace['echo_id'][echo_id] ~= nil do
			echo_id=math.random(0x0, 0xffff)
		end
		trace['echo_id'][echo_id]=i
		trace['hop'][i]={}
		trace['hop'][i]['from']=0
		trace['hop'][i]['rtt']=0
		trace['hop'][i]['reply_ttl']=0
		if i>=begin_hop  and i <=end_hop then			--只对指定范围进行，探测
			if VERBOSE >= 1 then
				io.write("--send ping packet ",i," ",echo_id,"\n")
			end
			set_ttl_to_ping(trace,i,echo_id,send_l3_sock,iface.device)
		end
	end
	stdnse.sleep(1)
	repeat
		if coroutine.status(icmp_reply_listener_handler) =="dead" then
			icmp_reply_listener_handler=nil
		else
			if VERBOSE >= 1 then
				print("wait icmp port unreachable listener end...")
			end
			icmp_reply_listener_signal['status'] = 1
			icmp_reply_listener_condvar("wait")
		end
	until icmp_reply_listener_handler==nil

	local return_trace={}
	return_trace['hop']={}
	return_trace['rtt']={}
	return_trace['reply_ttl']={}
	return_trace['start']=1
	return_trace['end']=trace['end']
	return_trace['dst']=dst_ip
	return_trace['rst']=8 --quicktrace type
	if VERBOSE >= 2 then
		io.write("Quicktrace: ",dst_ip , " hop ",1," - ",trace['end'] ,"\n")
	end
	for i =1,trace['end'] do
		return_trace['hop'][i]=trace['hop'][i]['from']
		return_trace['rtt'][i]=trace['hop'][i]['rtt']
		return_trace['reply_ttl'][i]=trace['hop'][i]['reply_ttl']
		if VERBOSE >= 2 then
			io.write(i,' ',trace['hop'][i]['from']," ",trace['hop'][i]['reply_ttl']," ",trace['hop'][i]['rtt'],"ms\n")
		end
	end
	send_l3_sock:ip_close()

	return return_trace
end

return quicktrace
