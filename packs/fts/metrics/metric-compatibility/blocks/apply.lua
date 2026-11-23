return function(p)
 local scale=fb.block('metrics.scale',{names={'latency'},input_unit='ms',output_unit='s',factor=0.001,numeric_policy='allow_double'})
 local rename=fb.block('metrics.rename',{mapping={latency='latency_seconds'}})
 return function(metric) if metric.type~='gauge' then return end;scale(metric);rename(metric) end
end
