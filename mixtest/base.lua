local stdnse = require "stdnse"
local ipOps = require "ipOps"
local math = require "math"
local bit = require "bit"
local bin = require "bin"
local string = require "string"
--
--ICMP	TYPE
ICMP_ECHOREPLY		=0	--/*	Echo	Reply		*/
ICMP_DEST_UNREACH	=3	--/*	Destination	Unreachable	*/
ICMP_SOURCE_QUENCH	=4	--/*	Source	Quench	*/
ICMP_REDIRECT		=5	--/*	Redirect	(change	route)	*/
ICMP_ECHO			=8	--/*	Echo	Request		*/
ICMP_TIME_EXCEEDED	=11	--/*	Time	Exceeded	*/
ICMP_PARAMETERPROB	=12	--/*	Parameter	Problem	*/
ICMP_TIMESTAMP		=13	--/*	Timestamp	Request	*/
ICMP_TIMESTAMPREPLY	=14	--/*	Timestamp	Reply	*/
ICMP_INFO_REQUEST	=15	--/*	Information	Request	*/
ICMP_INFO_REPLY		=16	--/*	Information	Reply	*/
ICMP_ADDRESS		=17	--/*	Address	Mask	Request	*/
ICMP_ADDRESSREPLY	=18	--/*	Address	Mask	Reply	*/
NR_ICMP_TYPES		=18--
	
--ICMP	CODE
ICMP_ECHOREPLY_CODE	=0
--/*	Codes	for	UNREACH.	*/--
ICMP_NET_UNREACH	=0	--/*	Network	Unreachable	*/
ICMP_HOST_UNREACH	=1	--/*	Host	Unreachable	*/
ICMP_PROT_UNREACH	=2	--/*	Protocol	Unreachable	*/
ICMP_PORT_UNREACH	=3	--/*	Port	Unreachable	*/
ICMP_FRAG_NEEDED	=4	--/*	Fragmentation	Needed/DF	set	*/
ICMP_SR_FAILED		=5	--/*	Source	Route	failed	*/
ICMP_NET_UNKNOWN	=6
ICMP_HOST_UNKNOWN	=7
ICMP_HOST_ISOLATED	=8
ICMP_NET_ANO		=9
ICMP_HOST_ANO		=10
ICMP_NET_UNR_TOS	=11
ICMP_HOST_UNR_TOS	=12
ICMP_PKT_FILTERED	=13	--/*	Packet	filtered	*/
ICMP_PREC_VIOLATION	=14	--/*	Precedence	violation	*/
ICMP_PREC_CUTOFF	=15	--/*	Precedence	cut	off	*/
NR_ICMP_UNREACH		=15	--/*	instead	of	hardcoding	immediate	value	*/
--
--/*	Codes	for	REDIRECT.	*/--
ICMP_REDIR_NET		=0	--/*	Redirect	Net		*/
ICMP_REDIR_HOST		=1	--/*	Redirect	Host	*/
ICMP_REDIR_NETTOS	=2	--/*	Redirect	Net	for	TOS	*/
ICMP_REDIR_HOSTTOS	=3	--/*	Redirect	Host	for	TOS	*/
--
--/*	Codes	for	TIME_EXCEEDED.	*/--
ICMP_EXC_TTL		=0	--/*	TTL	count	exceeded	*/
ICMP_EXC_FRAGTIME	=1	--/*	Fragment	Reass	time	exceeded	*/



--traceroute.h
TR_RESULT_GOTTHERE	=1    --/* Got the destination host.                */
TR_RESULT_UNREACH	=2    --/* Destination host/network is unreachable. */
TR_RESULT_TIMEOUT	=3    --/* Waiting for the return packets timeout.  */
TR_RESULT_MAXHOP	=4    --/* Traceroute reached the max hop.          */
TR_RESULT_LOOP		=5    --/* There is a loop in route.                */
TR_RESULT_FAKE		=6    --/* The return packet with a fake source IP  */
TR_RESULT_DESIGN	=7    --/* Traceroute finished by our design.       */
NR_TR_RESULT		=7    --/* The number of traceroute results.        */

MAX_TIMEOUT_PER_HOP	=3 --/* Max re-probing times when timeout.  */
MAX_TIMEOUT_HOPS   	=3    --/* Max continued probing hops when timeout. */
MAX_HOP           	=30    --/* Max hop(TTL) that traceroute can reach.  */



--/*	PPK_`type'	--	Probing	PacKet	type	*/
PPK_ICMPECHO		=1	--/*	ICMP	datagram	as	PING	send.	*/
PPK_ACK				=2	--/*	TCP	datagram	with	ACK	being	set.	*/
PPK_SYN				=3	--/*	TCP	datagram	with	SYN	being	set.	*/
PPK_FIN				=4	--/*	TCP	datagram	with	FIN	being	set.	*/
PPK_UDPBIGPORT		=5	--/*	UDP	datagram	with	a	large	dest	port	*/
--
NR_PPK_TYPE			=5	--/*	The	number	of	probing	packet	types.	*/
--/*	RPK_`type'	--	Return	(Respons--e)	PacKet	type	*/
--/*	NOT	a	return	packet.	*/
RPK_TIMEOUT			=6	--/*	Time	out	when	waiting	return	packet.	*/
RPK_ICMPECHO		=7	--/*	ICMP	ECHO	REPLY	for	ICMP	ECHO	REQUEST.	*/
RPK_RST				=8	--/*	TCP	RST	for	ACK	scanning.	*/
RPK_SYNACK			=9	--/*	TCP	SYN+ACK	for	SYN	scanning.	*/
RPK_RSTACK			=10	--/*	TCP	RST+ACK	for	SYN	or	FIN	scanning.	*/
RPK_TIMEEXC			=11	--/*	ICMP	TIME	EXCEEDED	for	TTL	being	ZERO.	*/


RPK_UNREACH	=12	

NR_PK_TYPE =(RPK_UNREACH + NR_ICMP_UNREACH)

--是否是icmp不可达信息
function IS_UNREACH(rpk_type)
	if rpk_type >= RPK_UNREACH and rpk_type<=NR_PK_TYPE then
		return 1
	else
		return 0
	end
end
-- "1.2.2.3/16" to 1.2.2.3 16
function str2cidr(str)
	local cidr_list=stdnse.strsplit("/",str)
	local cidr={}
	if #cidr_list ~= 2 then
		cidr['net']=str
		cidr['pfx']=32
		return cidr
	end
	cidr['net']=cidr_list[1]
	cidr['pfx']=tonumber(cidr_list[2])
	-- local number_ip = ipOps.todword(cidr['net'])
	-- print(number_ip)
	-- local a=3
	-- print(bit.lshift(a,2))
	-- print(bit.band(a,2))
	-- a = (a << 2)
	-- print(a)
	local ip=ipOps.ip_to_bin(cidr['net'])
	-- print("get cidr:",cidr['net'],cidr['pfx'])
	if not cidr['pfx'] or ( cidr['pfx'] < 0 ) or ( cidr['pfx'] > #ip  ) then
		print("Error: Invalid cidr prefix length.")
		cidr['net']=0
		cidr['pfx']=0
		return cidr
	end
	return cidr
end


---
-- Converts the supplied IPv4 address from a DWORD value into a dotted string.
--
-- For example, the address (((a*256+b)*256+c)*256+d) becomes a.b.c.d.
--
--@param ip DWORD representing an IPv4 address.
--@return The string representing the address.

---
-- Converts the supplied IPv4 address from a DWORD value into a dotted string. 
--
-- For example, the address (((a*256+b)*256+c)*256+d) becomes a.b.c.d. 
--
--@param ip DWORD representing an IPv4 address. 
--@return The string representing the address. 
function fastrace_fromdword( ip )
  if type( ip ) ~= "number" then
    stdnse.print_debug(1, "Error in ipOps.todword: Expected IPv4 address.")
    return nil
  end

  local n1 = bit.band(bit.rshift(ip, 24),  0x000000FF)
  local n2 = bit.band(bit.rshift(ip, 16),  0x000000FF)
  local n3 = bit.band(bit.rshift(ip, 8), 0x000000FF)
  local n4 = bit.band(bit.rshift(ip, 0), 0x000000FF)
  return string.format("%d.%d.%d.%d", n1, n2, n3, n4)
end


function HOSTADDR(ip,pfx)
	local number_ip = ipOps.todword(ip)
	if not number_ip then
		print("HOSTADDR:illege ip number:",ip,pfx)
		return nil
	end
	local ip= bit.band(number_ip,(bit.rshift(0xffffffff,pfx)))
	return ip 		--fastrace_fromdword(ip)
	-- body
end

function NETADDR(ip,pfx)
	local number_ip = ipOps.todword(ip)
	if not number_ip then
		print("NETADDR:illege ip number:",ip,pfx)
		return nil
	end
	local ip= bit.band(number_ip,(bit.lshift(0xffffffff,(32-pfx))))
	return ip 		--fastrace_fromdword(ip)
	-- body
end
function MID_IP(ip,pfx)
	local number_ip = ipOps.todword(ip)
	if not number_ip then
		print("NETADDR:illege ip number:",ip,pfx)
		return nil
	end
	local ip= bit.band(number_ip,(bit.lshift(0xffffffff,(32-pfx))))
	local half=bit.rshift(0xffffffff,pfx + 1)
	ip = ip + half
	return fastrace_fromdword(ip) 		--fastrace_fromdword(ip)
	-- body
end
function IP_INC(number_ip)
	if not number_ip then
		print("IP_INC:illege ip number:",number_ip)
		return nil
	end
	-- print("IP_INC:",number_ip)
	number_ip=number_ip+1
	return fastrace_fromdword(number_ip) 		--fastrace_fromdword(ip)
	-- body
end
function IP_DEC(number_ip)
	-- local number_ip = ipOps.todword(ip)
	if not number_ip then
		print("IP_DEC:illege ip number:",number_ip)
		return nil
	end
	number_ip=number_ip-1
	return fastrace_fromdword(number_ip) 		--fastrace_fromdword(ip)
	-- body
end
---
-- Calculates the first and last IP addresses of a range of addresses,
-- given an IP address in the range and a prefix length for that range
-- @param ip String representing an IPv4 or IPv6 address.  Shortened notation
--           is permitted.
-- @param prefix Number or a string representing a decimal number corresponding
--               to a prefix length.
-- @usage
-- first, last = ipOps.get_first_last_ip( "192.0.0.0", 26)
-- @return String representing the first IP address of the range denoted by
--         the supplied parameters (or <code>nil</code> in case of an error).
-- @return String representing the last IP address of the range denoted by
--         the supplied parameters (or <code>nil</code> in case of an error).
-- @return String error message in case of an error.
get_first_last_ip = function(ip, prefix)
  local err
  ip, err = ipOps.ip_to_bin(ip)
  if err then return nil, nil, err end
  -- print(ip)
  prefix = tonumber(prefix)
  if not prefix or prefix ~= math.floor(prefix) or prefix < 0 or prefix > #ip then
    return nil, nil, "Error in ipOps.get_first_last_ip: Invalid prefix."
  end

  local net = ip:sub(1, prefix)
  local first = ipOps.bin_to_ip(net .. ("0"):rep(#ip - prefix))
  local last  = ipOps.bin_to_ip(net .. ("1"):rep(#ip - prefix))
  return first, last
end
TRR2STRING = {
    "No result",
    "Got there",
    "Unreachable",
    "Timeout",
    "Reach max hop",
    "Route loop",
    "Fake source address",
    "End by design",
    "Quick trace",
}

OUTPUT_FILENAME		="fastrace.out"
-- OUTPUT_FILE_HANDLER	=nil
OUTPUT_TYPE			="stdout"
print_tr = function(tr,src_ip,OUTPUT_FILE_HANDLER,OUTPUT_TYPE)
    local i
    -- print(OUTPUT_TYPE)
    if OUTPUT_TYPE == "file" then
		-- fw=io.open(OUTPUT_FILENAME,'w')
		OUTPUT_FILE_HANDLER:write("Target ",tr['dst'] , " hop ",tr['start']," - ",tr['end'] ," from ",src_ip," ",TRR2STRING[tr['rst']+1],"\n")
	end
    io.write("Target ",tr['dst'] , " hop ",tr['start']," - ",tr['end'] ," from ",src_ip," ",TRR2STRING[tr['rst']+1],"\n") 	--加1 table从1开始
    if (tr['start'] <= 0 or tr['end'] <= 0) then
        return
    end 
    for i= tr['start'],tr['end'] do
    	if OUTPUT_TYPE == "file" then
	    	OUTPUT_FILE_HANDLER:write("~ ",i," ",tr['hop'][i]," ",tr['reply_ttl'][i]," ",tr['rtt'][i],"ms\n")
    	end
    	io.write("~ ",i," ",tr['hop'][i]," ",tr['reply_ttl'][i]," ",tr['rtt'][i],"ms\n")
    	
    end
end

PTYPE2STRING = {
    "I-EQ",
    "TACK",
    "TSYN",
    "TFIN",
    "UBIG",
    "TOUT",
    "I-ER",
    "TRST",
    "TS&A",
    "TR&A",
    "I-TX",
    "I-UN"
}
ptype2str = function(pack_type)
    if (pack_type > NR_PK_TYPE) then
        return "NULL"
    else
    	if IS_UNREACH(pack_type) ==1 then
    		return PTYPE2STRING[RPK_UNREACH]
    	else
    		return PTYPE2STRING[pack_type]
    	end
    end
end

print_ri = function(pi,rpk_type,from,rtt,reply_ttl)
	io.write("> ",pi['ttl']," ",pi['dst'],":",pi['dport']," ",ptype2str(pi['type']))
	if rpk_type==0 then
		print(" - error")
		return
	end
	if rpk_type==RPK_TIMEOUT then
		print(" - *")
		return 
	end
	io.write(" - ",from," ",ptype2str(rpk_type))
	if IS_UNREACH(rpk_type) == 1 then
		io.write(" ",rpk_type-RPK_UNREACH)
	end
	io.write(" ",reply_ttl," ",rtt," ms\n")
end
PROBING_TYPE_ARRAY	=	{
	PPK_SYN,	PPK_UDPBIGPORT,	PPK_ICMPECHO,
	PPK_SYN,	PPK_UDPBIGPORT,	PPK_ICMPECHO,--PPK_SYN,	PPK_SYN,	PPK_SYN,
	PPK_SYN,	PPK_UDPBIGPORT,	PPK_ICMPECHO,--PPK_UDPBIGPORT,	PPK_UDPBIGPORT,	PPK_UDPBIGPORT,
	PPK_SYN,	PPK_UDPBIGPORT,	PPK_ICMPECHO,--PPK_ICMPECHO,	PPK_ICMPECHO,	PPK_ICMPECHO,
	PPK_SYN,	PPK_UDPBIGPORT,	PPK_ICMPECHO,--PPK_SYN,	PPK_ACK,	PPK_SYN,
	PPK_SYN,	PPK_UDPBIGPORT,	PPK_ICMPECHO,--PPK_ICMPECHO,	PPK_SYN,	PPK_SYN
}
--traceroute UDP dport 53
PROBING_DPORT_ARRAY	=	{
	80,	54343,	0,
	80,	44343,	80,
	80,	55343,	49077,
	80,	56643,	0,
	80,	34343,	109,
	80,	64343,	443
}

NR_PROBING_ARRAY	=18
NR_PACKET_EACH_TYPE	=3


--ip头部协议字段含义
IPPROTO_UDP			=17
IPPROTO_ICMP		=1
IPPROTO_TCP			=6

--头部大小
IP_HEAD_SIZE		=20
ICMP_HEAD_SIZE		=8
UDP_HEAD_SIZE		=8
TCP_HEAD_SIZE		=20

MAX_PREFIX_LEN 		= 25
MIN_PREFIX_LEN 		= 22
MIN_NO_NEW_PREFIX 	= 24

VERBOSE				=0
DEBUG 				=0

PACKET_TYPE 		="MIX"
LAST_N_HOP_NUMBER	=4

ALL_LINK			=0	--all link we find
ALL_NODE			=0	--all node we found
ALL_SEND_PACKET		=0	--all packet send

RECURSION_TRACE		=0

IMPROVE				=0

BNP_REDUNDANCE_COUNT	=0 --tree trace 冗余数量
QUICKTRACE_REDUNDANCE_COUNT	=0

BNP_COUNT			=0
NNS_COUNT			=0
SAME_SUBNET_COUNT	=0
NO_NEW_LINK_NODE_COUNT	=0
QUICKTRACE_SENT			=0

EVERY_TATGET_SEND	={}	--发现新节点的发包数量

TEST_PFX_INFO		={}	--测试不同最大停止前缀下的发包量、节点、边获取情况


