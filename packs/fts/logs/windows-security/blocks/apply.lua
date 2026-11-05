return function(p)
 return function(log)
  local provider=log.body:get('ProviderName');local id=log.body:get('EventID')
  if not provider or provider:type()~='string' or provider:value()~='Microsoft-Windows-Security-Auditing' or not id then return end
  if id:type()~='int64' and id:type()~='uint64' then return end
  local code=id:value()
  if code=='4624' then log.body:set('event.outcome','success')
  elseif code=='4625' then log.body:set('event.outcome','failure') end
 end
end
