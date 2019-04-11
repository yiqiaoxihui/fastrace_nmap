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
	local echo_seq=math.random(0x0, 0xffff)
	local echo_id=math.random(0x0, 0xffff)
	-- echo_seq=1
	local str_hex_ip=ipOps.todword(pi['dst'])
	-- print(echo_seq,echo_id)
	local icmp_tole_rec_socket=nmap.new_socket()
	local capture_rule_echo_reply="(icmp[0]="..ICMP_ECHOREPLY.." and icmp[1]="..ICMP_ECHOREPLY_CODE.." and icmp[4:2]="..echo_id.." and icmp[6:2]="..echo_seq..")"
	--icmp[0]="..ICMP_TIME_EXCEEDED.." and icmp[1]="..ICMP_EXC_TTL.." and 
	local capture_rule_icmp_error="(icmp[34:2]="..echo_seq.." and icmp[32:2]="..echo_id..")"--(icmp[0]=11) and (icmp[1]=0) and 
	local capture_rule_icmp=capture_rule_echo_reply.." or "..capture_rule_icmp_error
	icmp_tole_rec_socket:pcap_open(device,128,false,capture_rule_icmp)
	icmp_tole_rec_socket:set_timeout(pi['wt'])

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
	send_l3_sock:ip_send(ip.buf)
	local status,len,l2_icmp_t_l,l3_icmp_tole,time=icmp_tole_rec_socket:pcap_receive()
	if status then
		-- print("get icmp packet back")
		local icmp_rpk_packet = packet.Packet:new(l3_icmp_tole, #l3_icmp_tole)
		from=icmp_rpk_packet['ip_src']
		-- for k,v in pairs(icmp_timeexc_packet) do
		-- 	print("ip:",k,v)
		-- end
		--rpk_type:PPK_ICMPECHO,RPK_ICMPECHO,RPK_UNREACH+code,RPK_TIMEEXC,0其他类型
		rpk_type=parsepack.get_ptype_icmp(icmp_rpk_packet,len)
		-- print(">HOP:",pi['ttl'],from)

	else
		-- print("!HOP:",pi['ttl'],"timeout")
		rpk_type=RPK_TIMEOUT

	end
	icmp_tole_rec_socket:close()
	return rpk_type,from
end


return prober