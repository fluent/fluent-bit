return function(p)
    assert(#p.target.field>0,'invalid_parameter')
    local seen={}
    for _,label in ipairs(p.labels) do
        assert(#label.name>0 and not seen[label.name],'invalid_parameter')
        seen[label.name]=true
    end
    return function(log)
        if #p.labels==0 then return end
        local labels=log.body:get(p.target.field)
        if labels and labels:type()~='map' then error('wrong_type',0) end
        labels=labels or log.body:ensure_map(p.target.field)
        for _,label in ipairs(p.labels) do
            if p.target.overwrite or not labels:get(label.name) then
                labels:set(label.name,fb.literal(label.value))
            end
        end
    end
end
