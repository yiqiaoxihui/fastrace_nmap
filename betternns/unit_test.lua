unit_test={}


function unit_test.reverse_trace_test()
	local trace={}
	trace['dst']="47.90.99.168"
	trace['start']=1
	trace['end']=16
	trace['hop']={}
	local cmptrace={}
	cmptrace['dst']="47.90.99.168"
	cmptrace['start']=1
	cmptrace['end']=27
	cmptrace['hop']={1,2,3,4,5,6,7,8,9,10,11,12,'101.4.112.62','101.4.117.26','101.4.112.42','101.4.114.250'}
	reverse_traceroute(trace,cmptrace)
end

return unit_test