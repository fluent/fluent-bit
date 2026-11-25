return function(p)
 return function(log)
  if fb.log_field(log,'trace_id') or fb.log_field(log,'span_id') then return end
  local trace=log.body:get('trace');local span=log.body:get('span')
  if not trace and not span then return end
  if not trace or not span or trace:type()~='string' or span:type()~='string' then error('wrong_type',0) end
  local t,s=trace:value(),span:value()
  if #t~=32 or #s~=16 or t:find('[^%x]') or s:find('[^%x]') or
     not t:find('[1-9a-fA-F]') or not s:find('[1-9a-fA-F]') then error('invalid_parameter',0) end
  fb.set_trace_context(log,t,s)
 end
end
