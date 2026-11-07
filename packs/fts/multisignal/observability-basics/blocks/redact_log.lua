-- A pack author owns this Lua policy; FTS provides the typed value API.
return function(parameters)
    local replacement = parameters.replacement

    return function(log)
        local kind = log.body:type()
        if kind ~= 'map' and kind ~= 'array' then
            error('wrong_type', 0)
        end
        fb.redact(log.body, parameters.keys, replacement)
        if log.attributes then fb.redact(log.attributes, parameters.keys, replacement) end
    end
end
