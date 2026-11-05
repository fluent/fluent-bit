return function(p)
 if p.field==p.destination then error('invalid_parameter',0) end
 fb.hmac_sha256(p.key_ref,'')
 return function(log)
  local selected=log.body:get(p.field);if not selected then return end
  if selected:type()~='string' then error('wrong_type',0) end
  local value=selected:value()
  if #value>65536 then error('invalid_parameter',0) end
  local message='fts-pseudonym-v1:'..#p.domain..':'..p.domain..#p.tenant..':'..p.tenant..#value..':'..value
  local digest=fb.hmac_sha256(p.key_ref,message)
  if log.body:get(p.destination) then error('collision',0) end
  log.body:set(p.destination,'hmac-sha256-v1:'..p.key_ref..':'..digest)
  log.body:remove(p.field)
 end
end
