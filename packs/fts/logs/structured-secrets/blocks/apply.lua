return function(p)
    return function(item) fb.redact(item.body or item.attributes,p.keys,p.replacement) end
end
