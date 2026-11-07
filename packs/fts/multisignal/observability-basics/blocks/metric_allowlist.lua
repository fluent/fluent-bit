return function(parameters)
    local keep = {}
    for _, name in ipairs(parameters.names) do keep[name] = true end
    return function(metric)
        if not keep[metric.name] then return fb.DROP end
    end
end
