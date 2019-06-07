local bin = require "bin"
local coroutine = require "coroutine"
local ipOps = require "ipOps"
local math = require "math"
local nmap = require "nmap"
local packet = require "packet"
local stdnse = require "stdnse"
local string = require "string"

require('parsepack')

prober={}
function prober.send_icmp_echo(pi,send_l3_sock,device)
	local rpk_type			--返回包类型
	local from 				--返回包ip
	local rtt 				--往返时延
	local reply_ttl 		--回包中ttl
	local echo_seq=math.random(0x0, 0xffff)
	local echo_id=math.random(0x0, 0xffff)
	-- echo_seq=1
	local str_hex_ip=ipOps.todword(pi['dst'])
	-- print(echo_seq,echo_id)
	local icmp_rec_socket=nmap.new_socket()
	local capture_rule_echo_reply="(icmp[0]="..ICMP_ECHOREPLY.." and icmp[1]="..ICMP_ECHOREPLY_CODE.." and icmp[4:2]="..echo_id.." and icmp[6:2]="..echo_seq..")"
	--icmp[0]="..ICMP_TIME_EXCEEDED.." and icmp[1]="..ICMP_EXC_TTL.." and 
	local capture_rule_icmp_error="(icmp[34:2]="..echo_seq.." and icmp[32:2]="..echo_id..")"--(icmp[0]=11) and (icmp[1]=0) and 
	local capture_rule_icmp=capture_rule_echo_reply.." or "..capture_rule_icmp_error
	icmp_rec_socket:pcap_open(device,128,false,capture_rule_icmp)
	icmp_rec_socket:set_timeout(pi['wt'])

	local ip=packet.Packet:new()
	ip.ip_bin_dst=ipOps.ip_to_str(pi['dst'])
	ip.ip_bin_src = ipOps.ip_to_str(pi['src'])
	ip.echo_data = "abc"
	ip.echo_seq = echo_seq
	ip.echo_id=echo_id
	ip.ip_offset=0
	ip:build_icmp_echo_request()
	ip:build_icmp_header()
	ip:build_ip_packet()
	ip:ip_set_ttl(pi['ttl'])
	local start_time,end_time
	start_time=stdnse.clock_ms()
	send_l3_sock:ip_send(ip.buf)
	send_l3_sock:ip_send(ip.buf)
	send_l3_sock:ip_send(ip.buf)
	local status,len,l2_icmp,l3_icmp,time=icmp_rec_socket:pcap_receive()
	if status then
		end_time=stdnse.clock_ms()
		rtt=end_time - start_time
		-- print("get icmp packet back")
		local l3_rpk_packet = packet.Packet:new(l3_icmp, #l3_icmp)
		reply_ttl=l3_rpk_packet.ip_ttl
		from=l3_rpk_packet['ip_src']
		-- for k,v in pairs(icmp_timeexc_packet) do
		-- 	print("ip:",k,v)
		-- end
		--rpk_type:PPK_ICMPECHO,RPK_ICMPECHO,RPK_UNREACH+code,RPK_TIMEEXC,0其他类型
		rpk_type=parsepack.get_ptype_icmp(l3_rpk_packet,#l3_icmp)
		-- print(">HOP:",pi['ttl'],from)
	else
		-- print("!HOP:",pi['ttl'],"timeout")
		rpk_type=RPK_TIMEOUT
	end
	icmp_rec_socket:close()
	return rpk_type,from,rtt,reply_ttl
end
--对udp,fastrace中探测包ip头部id为进程_pID,upd源端口为_SEQ
--type:1.收到大端口回复PPK_UDPBIGPORT，提取id为0，序列号seq为源端口,程序搞反了？2.收到端口不可达RPK_UNREACH + ihp->code;，提取id为原始报文ip头部id,
--
function prober.send_udp_big_port(pi,send_l3_sock,device)
	local rpk_type			--返回包类型
	local from 				--返回包ip
	local rtt 				--往返时延
	local reply_ttl 		--回包中ttl
	local rec_socket=nmap.new_socket()
	local hex_dst_ip=ipOps.todword(pi['dst'])
	--接收：返回报文为探测目标发送的，且端口与探测包相反的报文
	local capture_rule_udp="(udp[0:2]="..pi['dport'].." and udp[2:2]="..pi['sport'].." and src host "..pi['dst']..")"
	--接收：端口不可达，目标主机不可达，生存时间超时,且原始包中目标ip为探测目标pi['dst']
	local capture_rule_icmp_error="(icmp[24:4]="..hex_dst_ip.." and icmp[28:2]="..pi['sport'].." and icmp[30:2]="..pi['dport']..")"--(icmp[0]=11) and (icmp[1]=0) and 
	local capture_rule_icmp=capture_rule_udp.." or "..capture_rule_icmp_error
	rec_socket:pcap_open(device,128,false,capture_rule_icmp)
	rec_socket:set_timeout(pi['wt'])

    -- local pktbin = bin.pack("H",
    --   "4500 0014 0000 4000 8000 0000 0000 0000 0000 0000" ..
    --   "0000 0000 0800 0000"
    -- )
    local pktbin = bin.pack("H",
		"4500 003c 273a 0000 0411 2cb6 0a0a 0b82 bca6"..
		"908f 8be2 0035 0028 62fb 4041 4243 4445"..
		"4647 4849 4a4b 4c4d 4e4f 5051 5253 5455"..
		"5657 5859 5a5b 5c5d 5e5f"
    )
    local ip
    ip = packet.Packet:new(pktbin, pktbin:len())
    ip:udp_parse(false)

    ip:ip_set_bin_src(ipOps.ip_to_str(pi['src']))
    ip:ip_set_bin_dst(ipOps.ip_to_str(pi['dst']))
    ip:set_u8(ip.ip_offset + 9, packet.IPPROTO_UDP)
    ip.ip_p = packet.IPPROTO_UDP
    ip:ip_set_len(pktbin:len())
    ip:udp_set_sport(pi['sport'])	--math
    ip:udp_set_dport(pi['dport'])	--by send packet type array
    ip:udp_set_length(ip.ip_len - ip.ip_hl * 4)
    ip:udp_count_checksum()
    ip:ip_set_ttl(pi['ttl'])
    ip:ip_count_checksum()
	local start_time,end_time
	start_time=stdnse.clock_ms()
	send_l3_sock:ip_send(ip.buf)
	send_l3_sock:ip_send(ip.buf)
	send_l3_sock:ip_send(ip.buf)
	local status,len,l2_packet,l3_packet,time=rec_socket:pcap_receive()
	if status then
		-- print("get packet back")
		end_time=stdnse.clock_ms()
		rtt=end_time - start_time
		local l3_rpk_packet = packet.Packet:new(l3_packet, #l3_packet)
		reply_ttl=l3_rpk_packet.ip_ttl
		from=l3_rpk_packet['ip_src']
		--返回包为UDP包
		if l3_rpk_packet['ip_p']==IPPROTO_UDP then
			if #l3_packet - IP_HEAD_SIZE < UDP_HEAD_SIZE then
				print("!BROKEN PACKET:UDP_BIG_PORT_PACKET","l3_len:",#l3_packet,"from",l3_packet['src_ip'])
			end
			rpk_type = PPK_UDPBIGPORT
		--返回类型为ICMP包
		elseif l3_rpk_packet['ip_p']==IPPROTO_ICMP then
			--rpk_type:PPK_ICMPECHO,RPK_ICMPECHO,RPK_UNREACH+code,RPK_TIMEEXC,0其他类型
			rpk_type=parsepack.get_ptype_icmp(l3_rpk_packet,#l3_packet)
		else
			rpk_type=0
		end
		-- for k,v in pairs(l3_rpk_packet) do
		-- 	print("ip:",k,v)
		-- end
	else
		-- print("!HOP:",pi['ttl'],"timeout")
		rpk_type=RPK_TIMEOUT

	end
	rec_socket:close()
	return rpk_type,from,rtt,reply_ttl
end

function prober.send_tcp_syn(pi,send_l3_sock,device)
	local rpk_type			--返回包类型
	local from 				--返回包ip
	local rtt 				--往返时延
	local reply_ttl 		--回包中ttl
	local tcp_seq=math.random(0x0, 0xefffffff)
	local rec_socket=nmap.new_socket()
	local hex_dst_ip=ipOps.todword(pi['dst'])
	--接收：返回报文为探测目标发送的，且端口与探测包相反的报文
	local capture_rule_tcp="(tcp[0:2]="..pi['dport'].." and tcp[2:2]="..pi['sport'].." and src host "..pi['dst']..")"
	--接收：端口不可达，目标主机不可达，生存时间超时,且原始包中目标ip为探测目标pi['dst']
	local capture_rule_icmp_error="(icmp[24:4]="..hex_dst_ip.." and icmp[28:2]="..pi['sport'].." and icmp[30:2]="..pi['dport']..")"--(icmp[0]=11) and (icmp[1]=0) and 
	local capture_rule=capture_rule_tcp.." or "..capture_rule_icmp_error
	rec_socket:pcap_open(device,128,false,capture_rule)
	rec_socket:set_timeout(pi['wt'])
	local ip
    local pktbin = bin.pack("H",
      "4500 0014 0000 4000 8000 0000 0000 0000 0000 0000" ..
      "0000 0000 0000 0000 0000 0000 5002 0c00 0000 0000"
    )--sportdport   seq     ack_seq  header_len:6,
    								 --00000010:SYN
    								 --00010000:ACK
    								 --00000001:FIN
    ip = packet.Packet:new(pktbin, pktbin:len())
    ip:tcp_parse(false)
    ip:ip_set_bin_src(ipOps.ip_to_str(pi['src']))
    ip:ip_set_bin_dst(ipOps.ip_to_str(pi['dst']))
    -- ip:tcp_set_flags(2)	0000 0000,00 URG ACK PSH RST SYN FIN 
    ip:set_u8(ip.ip_offset + 9, packet.IPPROTO_TCP)
    ip.ip_p = packet.IPPROTO_TCP
    ip:ip_set_len(pktbin:len())
    ip:tcp_set_sport(pi['sport'])
    ip:tcp_set_dport(pi['dport'])
    ip:tcp_set_seq(tcp_seq)
    ip:tcp_count_checksum()
    ip:ip_set_ttl(pi['ttl'])
    ip:ip_count_checksum()
	local start_time,end_time
	start_time=stdnse.clock_ms()
	send_l3_sock:ip_send(ip.buf)
	send_l3_sock:ip_send(ip.buf)
	send_l3_sock:ip_send(ip.buf)
	local status,len,l2_packet,l3_packet,time=rec_socket:pcap_receive()
	if status then
		end_time=stdnse.clock_ms()
		rtt=end_time - start_time
		local l3_rpk_packet = packet.Packet:new(l3_packet, #l3_packet)
		reply_ttl=l3_rpk_packet.ip_ttl
		from=l3_rpk_packet['ip_src']
		--返回包为TCP包
		if l3_rpk_packet['ip_p']==IPPROTO_TCP then
			-- for k,v in pairs(l3_rpk_packet) do
			-- 	print("ip:",k,v)
			-- end
			rpk_type=parsepack.get_ptype_tcp(l3_rpk_packet,#l3_packet)
			
		--返回类型为ICMP包
		elseif l3_rpk_packet['ip_p']==IPPROTO_ICMP then
			--rpk_type:PPK_ICMPECHO,RPK_ICMPECHO,RPK_UNREACH+code,RPK_TIMEEXC,0其他类型
			rpk_type=parsepack.get_ptype_icmp(l3_rpk_packet,#l3_packet)
		else
			rpk_type=0
		end
	else
		-- print("!HOP:",pi['ttl'],"timeout")
		rpk_type=RPK_TIMEOUT

	end
	rec_socket:close()
	return rpk_type,from,rtt,reply_ttl
end

function prober.send_tcp_ack(pi,send_l3_sock,device)
	local rpk_type			--返回包类型
	local from 				--返回包ip
	local rtt 				--往返时延
	local reply_ttl 		--回包中ttl
	local tcp_seq=math.random(0x0, 0xefffffff)
	local rec_socket=nmap.new_socket()
	local hex_dst_ip=ipOps.todword(pi['dst'])
	--接收：返回报文为探测目标发送的，且端口与探测包相反的报文
	local capture_rule_tcp="(tcp[0:2]="..pi['dport'].." and tcp[2:2]="..pi['sport'].." and src host "..pi['dst']..")"
	--接收：端口不可达，目标主机不可达，生存时间超时,且原始包中目标ip为探测目标pi['dst']
	local capture_rule_icmp_error="(icmp[24:4]="..hex_dst_ip.." and icmp[28:2]="..pi['sport'].." and icmp[30:2]="..pi['dport']..")"--(icmp[0]=11) and (icmp[1]=0) and 
	local capture_rule=capture_rule_tcp.." or "..capture_rule_icmp_error
	rec_socket:pcap_open(device,128,false,capture_rule)
	rec_socket:set_timeout(pi['wt'])
	local ip
    local pktbin = bin.pack("H",
      "4500 0014 0000 4000 8000 0000 0000 0000 0000 0000" ..
      "0000 0000 0000 0000 0000 0000 5010 0c00 0000 0000"
    )--sportdport   seq     ack_seq  header_len:6,
    								 --00000010:SYN
    								 --00010000:ACK
    								 --00000001:FIN
    ip = packet.Packet:new(pktbin, pktbin:len())
    ip:tcp_parse(false)
    ip:ip_set_bin_src(ipOps.ip_to_str(pi['src']))
    ip:ip_set_bin_dst(ipOps.ip_to_str(pi['dst']))
    -- ip:tcp_set_flags(2)	0000 0000,00 URG ACK PSH RST SYN FIN 
    ip:set_u8(ip.ip_offset + 9, packet.IPPROTO_TCP)
    ip.ip_p = packet.IPPROTO_TCP
    ip:ip_set_len(pktbin:len())
    ip:tcp_set_sport(pi['sport'])
    ip:tcp_set_dport(pi['dport'])
    ip:tcp_set_seq(tcp_seq)
    ip:tcp_count_checksum()
    ip:ip_set_ttl(pi['ttl'])
    ip:ip_count_checksum()
	local start_time,end_time
	start_time=stdnse.clock_ms()
	send_l3_sock:ip_send(ip.buf)
	local status,len,l2_packet,l3_packet,time=rec_socket:pcap_receive()
	if status then
		end_time=stdnse.clock_ms()
		rtt=end_time - start_time
		local l3_rpk_packet = packet.Packet:new(l3_packet, #l3_packet)
		reply_ttl=l3_rpk_packet.ip_ttl
		-- print("get packet back")
		from=l3_rpk_packet['ip_src']
		--返回包为TCP包
		if l3_rpk_packet['ip_p']==IPPROTO_TCP then
			-- for k,v in pairs(l3_rpk_packet) do
			-- 	print("ip:",k,v)
			-- end
			rpk_type=parsepack.get_ptype_tcp(l3_rpk_packet,#l3_packet)
			
		--返回类型为ICMP包
		elseif l3_rpk_packet['ip_p']==IPPROTO_ICMP then
			--rpk_type:PPK_ICMPECHO,RPK_ICMPECHO,RPK_UNREACH+code,RPK_TIMEEXC,0其他类型
			rpk_type=parsepack.get_ptype_icmp(l3_rpk_packet,#l3_packet)
		else
			rpk_type=0
		end
	else
		-- print("!HOP:",pi['ttl'],"timeout")
		rpk_type=RPK_TIMEOUT

	end
	rec_socket:close()
	return rpk_type,from,rtt,reply_ttl
end

function prober.send_tcp_fin(pi,send_l3_sock,device)
	local rpk_type			--返回包类型
	local from 				--返回包ip
	local rtt 				--往返时延
	local reply_ttl 		--回包中ttl
	local tcp_seq=math.random(0x0, 0xefffffff)
	local rec_socket=nmap.new_socket()
	local hex_dst_ip=ipOps.todword(pi['dst'])
	--接收：返回报文为探测目标发送的，且端口与探测包相反的报文
	local capture_rule_tcp="(tcp[0:2]="..pi['dport'].." and tcp[2:2]="..pi['sport'].." and src host "..pi['dst']..")"
	--接收：端口不可达，目标主机不可达，生存时间超时,且原始包中目标ip为探测目标pi['dst']
	local capture_rule_icmp_error="(icmp[24:4]="..hex_dst_ip.." and icmp[28:2]="..pi['sport'].." and icmp[30:2]="..pi['dport']..")"--(icmp[0]=11) and (icmp[1]=0) and 
	local capture_rule=capture_rule_tcp.." or "..capture_rule_icmp_error
	rec_socket:pcap_open(device,128,false,capture_rule)
	rec_socket:set_timeout(pi['wt'])
	local ip
    local pktbin = bin.pack("H",
      "4500 0014 0000 4000 8000 0000 0000 0000 0000 0000" ..
      "0000 0000 0000 0000 0000 0000 5001 0c00 0000 0000"
    )--sportdport   seq     ack_seq  header_len:6,
    								 --00000010:SYN
    								 --00010000:ACK
    								 --00000001:FIN
    ip = packet.Packet:new(pktbin, pktbin:len())
    ip:tcp_parse(false)
    ip:ip_set_bin_src(ipOps.ip_to_str(pi['src']))
    ip:ip_set_bin_dst(ipOps.ip_to_str(pi['dst']))
    -- ip:tcp_set_flags(2)	0000 0000,00 URG ACK PSH RST SYN FIN 
    ip:set_u8(ip.ip_offset + 9, packet.IPPROTO_TCP)
    ip.ip_p = packet.IPPROTO_TCP
    ip:ip_set_len(pktbin:len())
    ip:tcp_set_sport(pi['sport'])
    ip:tcp_set_dport(pi['dport'])
    ip:tcp_set_seq(tcp_seq)
    ip:tcp_count_checksum()
    ip:ip_set_ttl(pi['ttl'])
    ip:ip_count_checksum()
	local start_time,end_time
	start_time=stdnse.clock_ms()
	send_l3_sock:ip_send(ip.buf)
	local status,len,l2_packet,l3_packet,time=rec_socket:pcap_receive()
	if status then
		-- print("get packet back")
		end_time=stdnse.clock_ms()
		rtt=end_time - start_time
		local l3_rpk_packet = packet.Packet:new(l3_packet, #l3_packet)
		reply_ttl=l3_rpk_packet.ip_ttl
		from=l3_rpk_packet['ip_src']
		--返回包为TCP包
		if l3_rpk_packet['ip_p']==IPPROTO_TCP then
			-- for k,v in pairs(l3_rpk_packet) do
			-- 	print("ip:",k,v)
			-- end
			rpk_type=parsepack.get_ptype_tcp(l3_rpk_packet,#l3_packet)
			
		--返回类型为ICMP包
		elseif l3_rpk_packet['ip_p']==IPPROTO_ICMP then
			--rpk_type:PPK_ICMPECHO,RPK_ICMPECHO,RPK_UNREACH+code,RPK_TIMEEXC,0其他类型
			rpk_type=parsepack.get_ptype_icmp(l3_rpk_packet,#l3_packet)
		else
			rpk_type=0
		end
	else
		-- print("!HOP:",pi['ttl'],"timeout")
		rpk_type=RPK_TIMEOUT

	end
	rec_socket:close()
	return rpk_type,from,rtt,reply_ttl
end

return prober
