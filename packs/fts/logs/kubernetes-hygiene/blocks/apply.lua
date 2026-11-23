return function(p)
    return function(log)
        for _,name in ipairs({'kubernetes','kubernetes_namespace'}) do
            local metadata = log.body:get(name)
            if metadata then
                if metadata:type()~='map' then error('wrong_type',0) end
                metadata:remove('annotations');metadata:remove('labels')
            end
        end
    end
end
