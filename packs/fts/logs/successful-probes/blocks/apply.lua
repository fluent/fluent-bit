return function(p)
    local drop=fb.block('logs.drop_matching',{condition={all={
        {selector={root='body',path={'path'}},op='in',values=p.paths},
        {selector={root='body',path={'status'}},op='eq',value=200},
        {selector={root='body',path={'duration_ms'}},op='gte',value=0},
        {selector={root='body',path={'duration_ms'}},op='lt',value=p.max_duration_ms}}}})
    return function(log)
        local status=log.body:get('status')
        if status and (status:type()=='int64' or status:type()=='uint64') then return drop(log) end
    end
end
