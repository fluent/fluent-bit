return function(p)
 local validate=fb.block('logs.validate_fields',{rules={{selector={root='body',path={'event_id'}},type='string',required=true}}})
 local trim=fb.block('fields.truncate',{target={root='body',path={'message'}},max_bytes=p.max_bytes,marker={root='body',path={'message.truncated'}}})
 return function(log) validate(log);trim(log) end
end
