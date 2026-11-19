return function(p)
    return function(log)
        fb.redact(log.body,p.keys,'[REDACTED]')
        if log.attributes then fb.redact(log.attributes,p.keys,'[REDACTED]') end
    end
end
