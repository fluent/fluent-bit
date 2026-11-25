return function(p)
 local time=fb.block('logs.parse_timestamp',{source={root='body',path={'eventTime'}}})
 return function(log)
  local version=log.body:get('eventVersion');if not version or version:type()~='string' or not version:value():match('^1%.%d+$') then return end
  local name=log.body:get('eventName');local origin=log.body:get('eventSource')
  if not name or not origin or name:type()~='string' or origin:type()~='string' then error('wrong_type',0) end
  time(log);log.body:set('cloud.provider','aws');log.body:set('event.action',name)
 end
end
