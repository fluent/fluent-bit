return function(p)
 return function(item)
  local root=item.body or item.resource.attributes
  if not root:get('service.name') then root:set('service.name',p.service) end
  if not root:get('deployment.environment.name') then root:set('deployment.environment.name',p.environment) end
 end
end
