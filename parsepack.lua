parsepack={}
--解析返回类型为ICMP包的类型
function parsepack.get_ptype_icmp(l3_icmp_packet,len)
	if len<(IP_HEAD_SIZE+ICMP_HEAD_SIZE) then
		print('!broken pkt,probe type:icmp!')
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
		if (len-icmp_payload_offset)<(IP_HEAD_SIZE+ICMP_HEAD_SIZE) then
			return 0
		else
			return RPK_UNREACH+icmp_code
		end
	elseif icmp_type==ICMP_TIME_EXCEEDED then				--返回类型:生存时间超时
		if (len-icmp_payload_offset)<(IP_HEAD_SIZE+ICMP_HEAD_SIZE) then
			return 0
		else
			return RPK_TIMEEXC
		end
	else
		return 0
	end
end

return parsepack