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

last_N_hop={}

local function fail(err) return ("\n  ERROR: %s"):format(err or "") end

local function last_n_hop_set_ttl_to_ping(iface,send_l3_sock,dst_ip,ttl,trace)
	local echo_id=math.random(0x0, 0xffff)
	while trace['echo_id'][echo_id] ~= nil do
		echo_id=math.random(0x0, 0xffff)
	end
	trace['echo_id'][echo_id]=ttl
	trace['hop'][ttl]={}
	trace['hop'][ttl]['from']=0
	trace['hop'][ttl]['rtt']=0
	trace['hop'][ttl]['rpk_type']=-1
	trace['hop'][ttl]['reply_ttl']=0
	-- if VERBOSE >= 1 then
	-- 	io.write("send ping packet ",i," ",echo_id,"\n")
	-- end
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
	send_l3_sock:ip_send(ip.buf)
end

local function get_distance_from_target_to_source(left_ttl)
	--print("left_ttl:",left_ttl)
	local ttl=0
	if left_ttl>30 then
		if left_ttl>64 then
			if left_ttl>128 then
				if left_ttl>200 then
					ttl=255-left_ttl
				else
					ttl=200-left_ttl
				end
			else
				ttl=128-left_ttl
			end
		else
			ttl=64-left_ttl
		end
	else
		ttl=30-left_ttl
	end
	return ttl+1
end

function icmp_reply_listener(dst_ip,trace,send_l3_sock,icmp_reply_listener_signal,device,VERBOSE)
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
	icmp_rec_socket:set_timeout(3000)
 
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
				if echo_id ~= nil and trace['echo_id'][echo_id] ~= nil then
					send_ttl = trace['echo_id'][echo_id]
					if VERBOSE >= 3 then
						print("icmp_reply_listener, RPK_ICMPECHO",echo_id,send_ttl)
					end
					-- if trace['end'] == -1 then
					-- 	trace['end'] =send_ttl
					-- elseif trace['end'] > send_ttl then
					-- 	trace['end'] = send_ttl
					-- end
					trace['hop'][send_ttl]['from']=from
					trace['hop'][send_ttl]['rpk_type']=0
					trace['hop'][send_ttl]['reply_ttl']=reply_ttl
					trace['hop'][send_ttl]['rtt']=end_time - trace['rtt'][send_ttl]['start_time']
				else
					if VERBOSE >= 1 then
						print("icmp_reply_listener, ERROR:not find echo_id in trace table:",echo_id)
					end
				end
			end
			if icmp_type == 11 and icmp_code == 0 then
				if (#l3_icmp-l3_rpk_packet['icmp_payload_offset'])<(IP_HEAD_SIZE+ICMP_HEAD_SIZE) then
					if VERBOSE >= 3 then
						print("!BROKEN PACKET:ICMP_DEST_UNREACH","l3_len:",l3_len,"from",l3_rpk_packet['src_ip'])
					end
				else
					local raw_sender_data_in_l3_rpk_packet=l3_icmp:sub(l3_rpk_packet.icmp_payload_offset+1)
					local raw_sender_packet=packet.Packet:new(raw_sender_data_in_l3_rpk_packet,#raw_sender_data_in_l3_rpk_packet)

					echo_id=raw_sender_packet:u16(raw_sender_packet.icmp_offset + 4)
					--echo_id = raw_sender_packet['echo_id']
					if echo_id ~= nil and trace['echo_id'][echo_id] ~= nil then
						send_ttl = trace['echo_id'][echo_id]
						if VERBOSE >= 3 then
							print("icmp_reply_listener, ICMP_EXC_TTL",echo_id,send_ttl)
						end
						if trace['start'] == -1 then
							trace['start'] = send_ttl
						elseif trace['start'] > send_ttl then
							trace['start'] = send_ttl
						end
						trace['hop'][send_ttl]['from']=from
						trace['hop'][send_ttl]['rpk_type']=11
						trace['hop'][send_ttl]['reply_ttl']=reply_ttl
						trace['hop'][send_ttl]['rtt']=end_time - trace['rtt'][send_ttl]['start_time']
					else
						if VERBOSE >= 1 then
							print("icmp_reply_listener, ERROR:not find echo_id in trace table:",echo_id)
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
				print("icmp_reply_listener, icmp reply linstener timeout")
			end
		end
	end
	icmp_rec_socket:close()
	condvar("signal")
end




--猜测到目标的网络距离
--
-- @param iface
-- @param send_l3_sock: l3 layer raw socket
-- @param icmp_echo_listener_signal:receive echo reply signal
-- @param icmp_tole_listener_signal:receive time limit signal
-- @param ip:target ip
-- trace['start'] ==-1:未获取一个中间路由器，~=-1:获取到的最小值的中间路由器
-- trace['start'] ==-1:未到达目标，~=-1:获取到的最小值的到目标的ttl
---
function guest_network_distance(iface,send_l3_sock,ip,last_n_hop,trace,VERBOSE)
	local pp=packet.Packet:new()
	local ttl_from_target_to_source=0
	local set_ttl=0
	local send_number=0
	local left_ttl=-1
	local first_ttl=64
	local result_hop_start=1 --实际需要从result_hop_start开始探测
	last_n_hop_set_ttl_to_ping(iface,send_l3_sock,ip,first_ttl,trace)
	stdnse.sleep(2)
	--TODO

	if trace['hop'][first_ttl]['rpk_type'] == 0 then
		-- icmp_echo_listener_signal['receive']=nil		--error:forget reset to nil,cause error guess
		left_ttl=trace['hop'][first_ttl]['reply_ttl']
		ttl_from_target_to_source=get_distance_from_target_to_source(left_ttl)
		if VERBOSE >= 1 then
			print("guest_network_distance, FIRST PREDICT PING SUCCESS",ip,left_ttl,ttl_from_target_to_source)
		end
		if ttl_from_target_to_source>30 or ttl_from_target_to_source <5 then  	--avoid too big ttl
			set_ttl=15
		else
			set_ttl=ttl_from_target_to_source
		end
		send_number=send_number+1
		last_n_hop_set_ttl_to_ping(iface,send_l3_sock,ip,set_ttl,trace)
		stdnse.sleep(1) 	--test,网络延迟，必须等待2秒

		if trace['hop'][set_ttl]['rpk_type'] == 0 then --到达目标，减小ttl
			if VERBOSE >= 1 then
				print("guest_network_distance, FIRST PREDICT TTL echo reply",ip,ttl_from_target_to_source)
			end
			while true do
				set_ttl=set_ttl-1
				send_number=send_number+1
				last_n_hop_set_ttl_to_ping(iface,send_l3_sock,ip,set_ttl,trace)
				stdnse.sleep(1)
				if trace['hop'][set_ttl]['rpk_type'] == 0 then
					if trace['end'] == -1 then
						trace['end'] =set_ttl
					elseif trace['end'] > set_ttl then
						trace['end'] = set_ttl
					end
					if VERBOSE >= 2 then
						print("guest_network_distance, CONTINUE RECEIVE REPLY ECHO",ip,set_ttl)
					end
				elseif trace['hop'][set_ttl]['rpk_type'] == 11 then
					if VERBOSE >= 2 then
						print("guest_network_distance, BREAK BY REPLY ECHO TO EXCEED",ip,set_ttl)
					end
					break
				else
					if VERBOSE >= 2 then
						print("guest_network_distance, NOTHING RECEIVE",ip,set_ttl)
					end
				end
				if set_ttl<=1 then
					if VERBOSE >= 1 then
						print("guest_network_distance, set_ttl to zero",ip,set_ttl)
					end
					break
				end
			end
			--获取倒数last_n_hop跳
			if VERBOSE >= 1 then
				print("guest_network_distance, start,end:",trace['start'],trace['end'])
			end
			if trace['end'] ~= -1 then
				result_hop_start = trace['end'] - last_n_hop
				if result_hop_start <=0 then
					result_hop_start=1
				end
				for i= result_hop_start , trace['end'] do
					last_n_hop_set_ttl_to_ping(iface,send_l3_sock,ip,i,trace)
				end
			else
				if VERBOSE >= 1 then
					print("guest_network_distance, NO REACH TARGET ",ip,ttl_from_target_to_source)
				end
			end
		elseif trace['hop'][set_ttl]['rpk_type'] == 11 then
			if VERBOSE >= 1 then
				print("guest_network_distance, FIRST PREDICT TTL time limit",ip,ttl_from_target_to_source)
			end
			while true do
				set_ttl=set_ttl+1
				send_number=send_number+1
				last_n_hop_set_ttl_to_ping(iface,send_l3_sock,ip,set_ttl,trace)
				stdnse.sleep(1)
				if trace['hop'][set_ttl]['rpk_type'] == 0 then
					if trace['end'] == -1 then
						trace['end'] =set_ttl
					elseif trace['end'] > set_ttl then
						trace['end'] = set_ttl
					end
					if VERBOSE >= 2 then
						print("guest_network_distance, BREAK BY EXCEED TO REPLY ECHO",ip,set_ttl)
					end
					break
				elseif trace['hop'][set_ttl]['rpk_type'] == 11 then
					if VERBOSE >= 2 then
						print("guest_network_distance, CONTINUE RECEIVE EXCEED",ip,set_ttl)
					end
				else
					if VERBOSE >= 2 then
						print("guest_network_distance, NOTHING RECEIVE",ip,set_ttl)
					end
				end
				if set_ttl>35 then
					if VERBOSE >= 1 then
						print("guest_network_distance, STOP BY more than 35",ip,set_ttl)
					end
					break
				end
			end
			--获取倒数last_n_hop跳
			if VERBOSE >= 1 then
				print("guest_network_distance, start,end:",trace['start'],trace['end'])
			end
			if trace['end'] ~= -1 then
				result_hop_start = trace['end'] - last_n_hop 	--规范实际开始跳数
				if result_hop_start <=0 then
					result_hop_start=1
				end
				if trace['start'] == -1 then   					--未收到任何生存时间超时报文
					trace['start'] = result_hop_start			--从result_hop_start 开始
				elseif trace['start'] <= result_hop_start then	--trace['start'] 覆盖了result_hop_start，直接返回
					return 0
				else
				end
				for i = result_hop_start , trace['end'] do
					last_n_hop_set_ttl_to_ping(iface,send_l3_sock,ip,i,trace)
				end
			else
				if VERBOSE >= 1 then
					print("guest_network_distance, NO REACH TARGET ",ip,ttl_from_target_to_source)
				end
			end
		else
			if VERBOSE >= 1 then
				print("guest_network_distance, FIRST PREDICT TTL no reply",ip,ttl_from_target_to_source)
			end
			-- set_ttl=ttl_from_target_to_source
			while true do
				set_ttl=set_ttl+1
				send_number=send_number+1
				last_n_hop_set_ttl_to_ping(iface,send_l3_sock,ip,set_ttl,trace)
				stdnse.sleep(1)
				if trace['hop'][set_ttl]['rpk_type'] == 0 then
					if trace['end'] == -1 then
						trace['end'] =set_ttl
					elseif trace['end'] > set_ttl then
						trace['end'] = set_ttl
					end
					if VERBOSE >= 2 then
						print("guest_network_distance, BREAK BY EXCEED TO REPLY ECHO",ip,set_ttl)
					end
					break
				elseif trace['hop'][set_ttl]['rpk_type'] == 11 then
					if VERBOSE >= 2 then
						print("guest_network_distance, CONTINUE RECEIVE EXCEED",ip,set_ttl)
					end
				else
					if VERBOSE >= 2 then
						print("guest_network_distance, NOTHING RECEIVE",ip,set_ttl)
					end
				end
				if set_ttl>35 then
					if VERBOSE >= 1 then
						print("guest_network_distance, STOP BY more than 35",ip,set_ttl)
					end
					break
				end
			end
			if VERBOSE >= 1 then
				print("guest_network_distance, start,end:",trace['start'],trace['end'])
			end
			if trace['end'] ~= -1 then
				result_hop_start = trace['end'] - last_n_hop 	--规范实际开始跳数
				if result_hop_start <=0 then
					result_hop_start=1
				end
				if trace['start'] == -1 then   					--未收到任何生存时间超时报文
					trace['start'] = result_hop_start			--从result_hop_start 开始
				elseif trace['start'] <= result_hop_start then	--trace['start'] 覆盖了result_hop_start，直接返回
					return 0
				else

				end
				for i = result_hop_start , trace['end'] do
					last_n_hop_set_ttl_to_ping(iface,send_l3_sock,ip,i,trace)
				end
			else
				if VERBOSE >= 1 then
					print("guest_network_distance, NO REACH TARGET ",ip,ttl_from_target_to_source)
				end
			end
			--mid_ttl=mid_ttl+0.1		--ip:90.196.109.225, left_ttl=9,right_ttl=10, mid_ttl=9,no any reply
		end
	else
		if VERBOSE >= 1 then
			print("guest_network_distance, FIRST PREDICT PING FAIL EXIT",ip,ttl_from_target_to_source)
		end
	end

	return 0
	-- body
end
-- The Action Section --
--action = function(host, port)

function last_N_hop.last_n_hop_main(dst_ip,last_n_hop,iface,VERBOSE)
	--建立发送l3层报文的raw socket
	--用于发送设置了ttl的探测末跳报文
	local send_l3_sock = nmap.new_dnet()
	send_l3_sock:ip_open()
	if VERBOSE >= 1 then
		io.write("last hop action,target: ",dst_ip," hops: ",last_n_hop,"\n")
	end
	local trace={}
	trace['ip_bin_src']=ipOps.ip_to_str(iface.address)
	trace['ip_bin_dst']=ipOps.ip_to_str(dst_ip)
	trace['hop']={}
	trace['echo_seq']={}
	trace['echo_id']={}
	trace['rtt']={}
	trace['start']=-1
	trace['end']=-1
	trace['last_n_hop']=last_n_hop
	local icmp_reply_listener_signal={}
	local icmp_reply_listener_condvar = nmap.condvar(icmp_reply_listener_signal)
	icmp_reply_listener_signal['status']=0 	--监听结束信号
	icmp_reply_listener_signal['icmp_pu']=0 	--是否收到icmp端口不可达信号
	local icmp_reply_listener_handler=stdnse.new_thread(icmp_reply_listener,dst_ip,trace,send_l3_sock,icmp_reply_listener_signal,iface.device,VERBOSE)

	stdnse.sleep(2)  --test,必须等待，否则线程未启动完成，可能已经发送了探测包
	guest_network_distance(iface,send_l3_sock,dst_ip,last_n_hop,trace,VERBOSE)
	stdnse.sleep(2)  --等待收包完毕
	repeat
		if coroutine.status(icmp_reply_listener_handler) =="dead" then
			icmp_reply_listener_handler=nil
		else
			if VERBOSE >= 1 then
				if VERBOSE >= 1 then
					print("last_n_hop_main, wait icmp port unreachable listener end...")
				end
			end
			icmp_reply_listener_signal['status'] = 1
			icmp_reply_listener_condvar("wait")
		end
	until icmp_reply_listener_handler==nil

	send_l3_sock:ip_close()
	local result_hop_start=trace['end'] - last_n_hop
	if result_hop_start <=0 then
		result_hop_start=1
	end

	io.write("Target ",dst_ip , " hop ",result_hop_start," - ",trace['end'] ,"\n")
	if trace['end'] ~=-1 then
		for i = result_hop_start,trace['end'] do
			io.write(i,' ',trace['hop'][i]['from']," ",trace['hop'][i]['reply_ttl']," ",trace['hop'][i]['rtt'],"ms\n")
		end
	end
	return true
end

return last_N_hop