return function(p)
 return function(log)
  local kind=log.body:get('Type');local action=log.body:get('Action')
  if not kind or kind:type()~='string' or (kind:value()~='TRAFFIC' and kind:value()~='THREAT') then return end
  if not action or action:type()~='string' then return end
  if action:value()=='allow' or action:value()=='deny' or action:value()=='drop' then log.body:set('network.action',action) end
 end
end
