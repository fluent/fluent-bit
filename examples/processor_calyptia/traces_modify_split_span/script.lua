local i = 0
function process_traces(tag, ts, span, metadata)
  i = i + 1
  local split = span.name ~= 'main'
  if split then
    span.name = 'hello-'..tostring(i)
  end
  -- modify some random attributes so that the output is deterministic
  span.traceId = 'abababab'
  span.spanId = 'cdcdcdcd'
  span.parentSpanId = 'efefefef'
  span.startTimeUnixNano = 100
  span.endTimeUnixNano = 200
  if span.attributes then
    for k, _ in pairs(span.attributes) do
      -- we can only have 1 key in a map or the output will not be deterministic
      -- due to random table iteration order when converting back to C
      if k ~= 'my_array' then
        span.attributes[k] = nil
      end
    end
  end
  if span.events then
      span.events[1].timeUnixNano = 300
      for k, _ in pairs(span.events[1].attributes) do
        if k ~= 'syscall 2' then
          -- we can only have 1 key in a map or the output will not be deterministic
          -- due to random table iteration order when converting back to C
          span.events[1].attributes[k] = nil
        end
      end
  end
  if span.links and span.links[1] then
      span.links[1].traceId = 'AAAAAAAA'
  end
  if split then
    return MODIFY, ts, {span, span}
  end
  return MODIFY, ts, span
end
