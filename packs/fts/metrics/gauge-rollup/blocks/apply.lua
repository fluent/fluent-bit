return function(p)
    assert(p.operation=='sum' or p.operation=='mean' or p.operation=='min' or
        p.operation=='max' or p.operation=='count','invalid_parameter')
    local names={}
    for _,name in ipairs(p.names) do names[name]=true end
    local window=fb.metric_window{interval_ms=p.interval_ms,max_samples=p.max_samples}
    return function(metric)
        if metric.type~='gauge' or not names[metric.name] or metric.datapoints:len()==0 then return end
        local key=fb.metric_window_key(metric)
        local previous,state,samples=window:get(key)
        local next_state=fb.gauge_rollup(metric,previous,state,samples,p.operation)
        return window:hold(key,metric,next_state)
    end
end
