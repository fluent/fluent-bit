return function(p)
 if p.layout~='aws-default-v2' then error('invalid_parameter',0) end
 local names={'version','account_id','interface_id','srcaddr','dstaddr','srcport','dstport','protocol','packets','bytes','start','end','action','log_status'}
 local numeric={version=true,srcport=true,dstport=true,protocol=true,packets=true,bytes=true,start=true,['end']=true}
 return function(log)
  local raw=log.body:get('message');if not raw then return end
  if raw:type()~='string' then error('wrong_type',0) end
  local text=raw:value();if #text>4096 then error('invalid_parameter',0) end
  local fields={};for field in text:gmatch('%S+') do fields[#fields+1]=field end
  if fields[1]~='2' then return end
  if #fields~=14 then error('invalid_parameter',0) end
  if log.body:get('flow') then error('collision',0) end
  local flow=fb.map()
  for i,name in ipairs(names) do
   local v=fields[i]
   if v~='-' then
    if name=='action' and v~='ACCEPT' and v~='REJECT' then error('invalid_parameter',0) end
    if name=='log_status' and v~='OK' and v~='NODATA' and v~='SKIPDATA' then error('invalid_parameter',0) end
    if numeric[name] then if not v:match('^%d+$') then error('invalid_parameter',0) end;flow:set(name,fb.uint64(v))
    else flow:set(name,v) end
   end
  end
  log.body:set('flow',flow)
 end
end
