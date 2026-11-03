local fb = package.loaded.fluentbit
function fb.is_otel(log)
  local schema = rawget(log, 'context') and rawget(log, 'context').metadata:get('schema')
  return schema and schema:type() == 'string' and schema:value() == 'otlp' or false
end
local function read_map(map, key, created)
  local value = map:get(key)
  if value then return value end
  value = map:ensure_map(key)
  created[#created+1] = {map, key}
  return value
end
local function semantic(map, created)
  return setmetatable({}, {
    __index = function(_, key)
      if key == 'attributes' then return read_map(map, key, created) end
      local value = map:get(key); if value then return value:value() end
    end,
    __newindex = function(_, key, value)
      assert(key == 'name' or key == 'version' or key == 'schema_url', 'unsupported context property')
      assert(type(value) == 'string', 'context property must be a string')
      map:set(key, value)
    end,
    __metatable = 'telemetry context'
  })
end
function fb._attach(log)
  local created
  local context = rawget(log, 'context')
  local root_metadata = rawget(log, 'metadata')
  local otel = fb.is_otel(log)
  local function identity(name)
    -- Missing IDs are regenerated when the group is rebuilt.
    local value = rawget(context, 'metadata'):get(name)
    if value == nil then return nil end
    assert(value:type() == 'int64' or value:type() == 'uint64', 'invalid transport ID')
    return value:value()
  end
  local resource_id, scope_id
  if otel then
    created = {}
    resource_id = identity('resource_id')
    scope_id = identity('scope_id')
    log.resource = semantic(read_map(rawget(context, 'attributes'), 'resource', created), created)
    log.scope = semantic(read_map(rawget(context, 'attributes'), 'scope', created), created)
    log.attributes = read_map(read_map(rawget(log, 'metadata'), 'otlp', created), 'attributes', created)
  end
  local resource, scope, attrs = rawget(log, 'resource'), rawget(log, 'scope'), rawget(log, 'attributes')
  local original_time = otel and fb.log_field(log, 'timestamp')
  original_time = original_time and original_time:value()
  local function validate(sec, nsec)
    assert(rawget(log, 'context') == context, 'context root cannot be replaced')
    assert(rawget(log, 'metadata') == root_metadata, 'metadata root cannot be replaced')
    assert(fb.is_otel(log) == otel, 'transport schema cannot be changed')
    if otel then
      assert(rawget(log, 'resource') == resource and rawget(log, 'scope') == scope and rawget(log, 'attributes') == attrs,
             'semantic aliases cannot be replaced')
      assert(rawget(context, 'metadata'):get_string('schema') == 'otlp'
             and identity('resource_id') == resource_id
             and identity('scope_id') == scope_id,
             'transport identifiers cannot be changed')
      if rawget(log, 'timestamp').sec == sec and rawget(log, 'timestamp').nsec == nsec then
        local current = fb.log_field(log, 'timestamp')
        assert((current and current:value()) == original_time, 'change event time through log.timestamp')
      end
    end
  end
  return validate,created
end
function fb._cleanup(created)
  for i=#created,1,-1 do
    local map,key = created[i][1],created[i][2]
    -- A policy may have removed an ancestor through the advanced context API.
    local ok,value = pcall(function() return map:get(key) end)
    if ok and value and value:type() == 'map' and value:len() == 0 then
      map:remove(key)
    end
  end
end
function fb.attributes(log)
  assert(fb.is_otel(log), 'OTel log required')
  return rawget(log, 'attributes')
end
function fb.log_field(log, name)
  assert(fb.is_otel(log), 'OTel log required')
  local otlp = rawget(log, 'metadata'):get('otlp')
  return (otlp and otlp:get(name)) or rawget(log, 'metadata'):get(name)
end
function fb.set_severity(log, level)
  assert(fb.is_otel(log), 'OTel log required')
  local names = {trace=1, debug=5, info=9, information=9, informational=9,
                 warn=13, warning=13, error=17, fatal=21, critical=21}
  assert(type(level) == 'string', 'severity must be a named level')
  local number = names[level:lower()]; assert(number, 'unknown severity level')
  local otlp = rawget(log, 'metadata'):ensure_map('otlp')
  otlp:set('severity_text', level); otlp:set('severity_number', fb.int64(number))
end
function fb.set_trace_context(log, trace, span)
  assert(fb.is_otel(log), 'OTel log required')
  local function decode(s, length)
    assert(type(s) == 'string' and #s == length * 2 and not s:find('[^%x]')
           and s:find('[1-9a-fA-F]'), 'invalid correlation ID')
    return fb.bytes((s:gsub('..', function(pair) return string.char(tonumber(pair, 16)) end)))
  end
  local trace_value = decode(trace, 16); local span_value = decode(span, 8)
  local otlp = rawget(log, 'metadata'):ensure_map('otlp')
  otlp:set('trace_id', trace_value); otlp:set('span_id', span_value)
end
function fb._validate(log, original_sec, original_nsec, changed)
  if not fb.is_otel(log) then return end
  for _,kind in ipairs({'resource','scope'}) do
    local map = rawget(log, 'context').attributes:get(kind)
    if map then
    assert(map:type() == 'map', kind .. ' must be a map')
    for _,name in ipairs({'schema_url','name','version'}) do
      local value = map:get(name)
      assert(not changed[kind .. '.' .. name] or not value or value:type() == 'string', kind .. '.' .. name .. ' must be a string')
    end
    local attrs = map:get('attributes')
    if attrs and changed[kind .. '.attributes'] then
      assert(attrs:type() == 'map', kind .. '.attributes must be a map')
      local seen = {}
      for _,key in ipairs(attrs:keys()) do
        assert(not seen[key], 'duplicate attribute key'); seen[key] = true
      end
    end
    local count = map:get('dropped_attributes_count')
    if count and changed[kind .. '.dropped_attributes_count'] then
      assert(count:type() == 'int64' or count:type() == 'uint64', 'dropped count must be an integer')
      assert(count:number() >= 0 and count:number() <= 4294967295, 'dropped count out of range')
    end
  end
    end
  assert(rawget(log, 'attributes'):type() == 'map', 'log.attributes must be a map')
  local seen = {}
  for _,key in ipairs(changed.attributes and rawget(log, 'attributes'):keys() or {}) do
    assert(not seen[key], 'duplicate attribute key'); seen[key] = true
  end
  local otlp = rawget(log, 'metadata'):get('otlp')
  for _,name in ipairs({'severity_number','trace_flags','dropped_attributes_count'}) do
    local value = fb.log_field(log, name)
    if value and changed[name] then
      assert(value:type() == 'int64' or value:type() == 'uint64', name .. ' must be an integer')
      local number = value:number()
      assert(number>=0 and number <= (name == 'severity_number' and 24 or (name == 'trace_flags' and 255 or 4294967295)), name .. ' out of range')
    end
  end
  for _,name in ipairs({'trace_id','span_id'}) do
    local value = fb.log_field(log, name)
    if value and changed[name] then
      local str = value:value()
      assert(value:type() == 'bytes' and #str == (name == 'trace_id' and 16 or 8)
             and not str:match('^%z+$'), 'invalid ' .. name)
    end
  end
  local name = fb.log_field(log, 'event_name')
  assert(not changed.event_name or not name or name:type() == 'string', 'event_name must be a string')
  local severity = fb.log_field(log, 'severity_text')
  assert(not changed.severity_text or not severity or severity:type() == 'string', 'severity_text must be a string')
  for _,name in ipairs({'timestamp','observed_timestamp'}) do
    local value = fb.log_field(log, name)
    if value and changed[name] then
      assert(value:type() == 'uint64' or (value:type() == 'int64' and value:value():sub(1,1) ~= '-'),
             name .. ' must be a nonnegative integer')
    end
  end
  if rawget(log, 'timestamp').sec ~= original_sec or rawget(log, 'timestamp').nsec ~= original_nsec then
    local str = string.format('%.0f', rawget(log, 'timestamp').sec) .. string.format('%09d',rawget(log, 'timestamp').nsec)
    otlp:set('timestamp', fb.uint64(str))
  end
end
