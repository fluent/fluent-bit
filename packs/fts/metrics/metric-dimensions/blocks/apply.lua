return function(p)
    local aggregate = fb.block('metrics.aggregate_dimensions', {
        names=p.names, keep_attributes={}, operation='sum'
    })
    return function(metric)
        if metric.type == 'gauge' then return aggregate(metric) end
    end
end
