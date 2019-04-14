parsepack={}
--解析返回类型为ICMP包的类型
function parsepack.get_ptype_icmp(l3_icmp_packet,l3_len)
	if l3_len<(IP_HEAD_SIZE+ICMP_HEAD_SIZE) then
		print("!BROKEN PACKET:ICMP_PACKET","l3_len:",l3_len,"from",l3_icmp_packet['src_ip'])
		return 0
	end
	local icmp_type=l3_icmp_packet['icmp_type']
	local icmp_code=l3_icmp_packet['icmp_code']
	local icmp_payload_offset=l3_icmp_packet['icmp_payload_offset']
	if icmp_type==ICMP_ECHO then							--返回包类型:ping-echo?
		return PPK_ICMPECHO
	elseif icmp_type==ICMP_ECHOREPLY then					--返回类型:echo_reply
		return RPK_ICMPECHO
	elseif icmp_type==ICMP_DEST_UNREACH then				--返回类型:目标不可达
		if (l3_len-icmp_payload_offset)<(IP_HEAD_SIZE+ICMP_HEAD_SIZE) then
			print("!BROKEN PACKET:ICMP_DEST_UNREACH","l3_len:",l3_len,"from",l3_icmp_packet['src_ip'])
			return 0
		else
			return RPK_UNREACH+icmp_code
		end
	elseif icmp_type==ICMP_TIME_EXCEEDED then				--返回类型:生存时间超时
		if (l3_len-icmp_payload_offset)<(IP_HEAD_SIZE+ICMP_HEAD_SIZE) then
			print("!BROKEN PACKET:ICMP_TIME_EXCEEDED","l3_len:",l3_len,"from",l3_icmp_packet['src_ip'])
			return 0
		else
			return RPK_TIMEEXC
		end
	else
		return 0
	end
end

function parsepack.get_ptype_tcp(l3_tcp_packet,l3_len)
	if l3_len<(IP_HEAD_SIZE+TCP_HEAD_SIZE) then
		print("!BROKEN PACKET:TCP_SYN_PACKET","l3_len:",l3_len,"from",l3_tcp_packet['src_ip'])
		return 0
	end
	local urg=l3_tcp_packet['tcp_th_urg']
	local psh=l3_tcp_packet['tcp_th_push']
	local ack=l3_tcp_packet['tcp_th_ack']
	local syn=l3_tcp_packet['tcp_th_syn']
	local fin=l3_tcp_packet['tcp_th_fin']
	local rst=l3_tcp_packet['tcp_th_rst']
	if urg==true or psh==true then
		return 0
	end
	if fin==true then
		return PPK_FIN
	end
	if rst==true then
		if ack==true then		--maybe from syn ,fin scan
			return RPK_RSTACK
		else
			return RPK_RST
		end
		return 0
	end
	if syn==true then			--maybe from syn scan
		if ack==true then
			return RPK_SYNACK
		else
			return RPK_SYN
		end
		return 0
	end
	if ack==true then
		return PPK_ACK
	end
	return 0
end
return parsepack