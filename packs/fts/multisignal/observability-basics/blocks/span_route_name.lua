return function(parameters)
    return function(span)
        if span.kind ~= 2 then return end
        local route = span.attributes:get(parameters.route_attribute)
        if not route then return end
        if route:type() ~= 'string' then error('wrong_type', 0) end
        if #route:value() > 0 then span.name = route:value() end
    end
end
