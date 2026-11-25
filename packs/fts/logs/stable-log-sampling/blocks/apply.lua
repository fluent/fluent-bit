return function(p)
 if p.basis_points<0 or p.basis_points>10000 or p.basis_points~=math.floor(p.basis_points) then error('invalid_parameter',0) end
 return function(log)
  local level=log.body:get('level')
  if level and level:type()=='string' then
   local severity=level:value():upper()
   if severity=='ERROR' or severity=='FATAL' or severity=='CRITICAL' then return end
  end
  local selected=log.body:get(p.field);if not selected then return end
  if selected:type()~='string' then error('wrong_type',0) end
  local key=selected:value()
  local material='fts-sample-v1:'..#p.domain..':'..p.domain..#p.tenant..':'..p.tenant..#key..':'..key
  if fb.hash64_mod(material,10000)>=p.basis_points then return fb.DROP end
 end
end
