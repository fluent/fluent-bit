return function(parameters)
    local decide = fb.dedupe(parameters)
    return function(log)
        return decide(log)
    end
end
