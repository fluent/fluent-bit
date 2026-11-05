return function(p)
    local parse=fb.block('logs.parse_json',{source={root='body',path={'log'}},destination={root='body',path={'app'}},remove_source=true})
    local severity=fb.block('logs.normalize_severity',{source={root='body',path={'app','level'}},destination={root='body',path={'severity'}}})
    return function(log) parse(log);severity(log);fb.redact(log.body,p.keys,p.replacement) end
end
