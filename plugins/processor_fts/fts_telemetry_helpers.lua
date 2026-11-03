local fb = package.loaded.fluentbit
local kinds = {'gauge', 'sum', 'histogram', 'exponential_histogram', 'summary'}
local integer_properties = {kind=true, flags=true, dropped_attributes_count=true,
    dropped_events_count=true, dropped_links_count=true}

local function hex(bytes)
    return (bytes:gsub('.', function(c) return string.format('%02x', c:byte()) end))
end

local function unhex(text, size, optional)
    assert(type(text) == 'string', 'ID must be a hexadecimal string')
    if optional and text == '' then return fb.bytes('') end
    assert(#text == size * 2 and text:match('^[%x]+$') and not text:match('^0+$'), 'invalid ID')
    return fb.bytes((text:gsub('..', function(c) return string.char(tonumber(c, 16)) end)))
end

local function object(raw)
    return setmetatable({}, {
        __index=function(_, key)
            local value = raw:get(key)
            if not value then return nil end
            local kind = value:type()
            if key == 'trace_id' or key == 'span_id' or key == 'parent_span_id' then
                return hex(value:value())
            end
            if kind == 'string' or kind == 'bool' or kind == 'double' then return value:value() end
            if integer_properties[key] then return value:number() end
            return value
        end,
        __newindex=function(_, key, value)
            if key == 'trace_id' or key == 'span_id' or key == 'parent_span_id' then
                value = unhex(value, key == 'trace_id' and 16 or 8, key == 'parent_span_id')
            elseif integer_properties[key] and type(value) == 'number' then
                value = fb.int64(value)
            end
            raw:set(key, value)
        end,
        __metatable='FTS telemetry object'
    })
end

local roots = setmetatable({}, {__mode='k'})

local function metric_data(item)
    for _, kind in ipairs(kinds) do
        local data = item:get(kind)
        if data then return kind, data end
    end
    error('metric has no supported data type')
end

function fb._fts_wrap(root, signal, emissions, tag)
    local item = root:get('item')
    local view = object(item)
    local function context(key)
        local fields = object(root:get(key))
        return setmetatable({}, {
            __index=function(_, name)
                if name == 'schema_url' then return root:get_string(key .. '_schema_url') end
                return fields[name]
            end,
            __newindex=function(_, name, value)
                assert(name ~= 'attributes', 'change context attributes through set/remove')
                if name == 'schema_url' then root:set(key .. '_schema_url', value)
                else fields[name] = value end
            end,
            __metatable='FTS context'
        })
    end
    local resource, scope = context('resource'), context('scope')
    local proxy = setmetatable({}, {
        __index=function(_, key)
            if key == 'signal' then return signal end
            if key == 'tag' then return tag end
            if key == 'resource' then return resource end
            if key == 'scope' then return scope end
            if signal == 'metrics' then
                local kind, data = metric_data(item)
                if key == 'type' then return kind end
                if key == 'datapoints' then return data:get('data_points') end
                if key == 'aggregation_temporality' then
                    local value = data:get(key)
                    return value and ({[0]='unspecified',[1]='delta',[2]='cumulative'})[value:number()]
                end
                if key == 'is_monotonic' then
                    local value = data:get(key); return value and value:value()
                end
                if key == 'emit' then
                    return function()
                        assert(emissions, 'metric emission is unavailable')
                        emissions:append(root)
                        return fb._fts_wrap(emissions:get(emissions:len()), signal, nil, tag)
                    end
                end
            end
            return view[key]
        end,
        __newindex=function(_, key, value)
            assert(key ~= 'resource' and key ~= 'scope' and key ~= 'signal' and key ~= 'tag',
                'change context fields through their existing views')
            if signal == 'metrics' then
                local kind, data = metric_data(item)
                if key == 'datapoints' then data:set('data_points', value); return end
                if key == 'aggregation_temporality' then
                    local number = ({unspecified=0,delta=1,cumulative=2})[value]
                    assert(number and kind ~= 'gauge' and kind ~= 'summary', 'invalid temporality')
                    data:set(key, fb.int64(number)); return
                end
                if key == 'is_monotonic' then
                    assert(kind == 'sum' and type(value) == 'boolean', 'monotonicity requires a sum')
                    data:set(key, value); return
                end
                if key == 'type' then
                    assert((kind == 'gauge' or kind == 'sum') and (value == 'gauge' or value == 'sum'),
                        'only gauge/sum conversion preserves the datapoint model')
                    if value == kind then return end
                    local points = data:get('data_points')
                    local converted = fb.map(); converted:set('data_points', points)
                    if value == 'sum' then
                        converted:set('aggregation_temporality', fb.int64(2))
                        converted:set('is_monotonic', false)
                    end
                    item:remove(kind); item:set(value, converted); return
                end
            end
            view[key] = value
        end,
        __metatable='FTS telemetry record'
    })
    roots[proxy] = root
    return proxy
end

function fb.metric_value(point)
    return point:get('as_int') or point:get('as_double')
end

function fb.set_metric_value(point, value)
    if type(value) == 'number' then
        assert(value == value and value ~= math.huge and value ~= -math.huge, 'nonfinite metric edit')
        point:remove('as_int'); point:set('as_double', value)
    else
        local kind = value:type()
        assert(kind == 'int64' or kind == 'uint64' or kind == 'double', 'metric value must be numeric')
        if kind == 'double' then point:remove('as_int'); point:set('as_double', value)
        else point:remove('as_double'); point:set('as_int', value) end
    end
end

function fb.copy_metric(metric, name, description, unit)
    local copy = metric:emit()
    if name then copy.name = name end
    if description then copy.description = description end
    if unit then copy.unit = unit end
    return copy
end

function fb.scale_metric(metric, factor, unit)
    assert(type(factor) == 'number' and factor > 0 and factor < math.huge, 'scale must be finite and positive')
    assert(metric.type ~= 'exponential_histogram', 'exponential histogram scaling requires bucket remapping')
    for i=1,metric.datapoints:len() do
        local point = metric.datapoints:get(i)
        local value = fb.metric_value(point)
        if value then
            local number = value:number() * factor
            if value:type() == 'int64' and factor == math.floor(factor) then
                fb.set_metric_value(point, fb.int64(number))
            else fb.set_metric_value(point, number) end
        else
            for _, key in ipairs({'sum','min','max'}) do
                local number = point:get_number(key)
                if number then point:set(key, number * factor) end
            end
            local bounds = point:get('explicit_bounds')
            if bounds then
                for j=1,bounds:len() do bounds:set(j, bounds:get(j):number() * factor) end
            end
            local quantiles = point:get('quantile_values')
            if quantiles then
                for j=1,quantiles:len() do
                    local quantile = quantiles:get(j)
                    quantile:set('value', quantile:get_number('value') * factor)
                end
            end
        end
        local exemplars = point:get('exemplars')
        if exemplars then
            for j=1,exemplars:len() do
                local exemplar = exemplars:get(j)
                local original = fb.metric_value(exemplar)
                if original then
                    local scaled = original:number() * factor
                    if original:type() == 'int64' and factor == math.floor(factor) then
                        fb.set_metric_value(exemplar, fb.int64(scaled))
                    else
                        fb.set_metric_value(exemplar, scaled)
                    end
                end
            end
        end
    end
    if unit then metric.unit = unit end
end

function fb.extract_metric(metric, field, name, monotonic)
    assert(field == 'count' or field == 'sum' or field == 'avg', 'unsupported extraction')
    assert(metric.type == 'histogram' or metric.type == 'exponential_histogram' or metric.type == 'summary',
        'extraction requires a distribution')
    local points = fb.array()
    for i=1,metric.datapoints:len() do
        local source = metric.datapoints:get(i)
        local value = source:get(field == 'avg' and 'sum' or field)
        local count = source:get('count')
        if value and (field ~= 'avg' or count:number() ~= 0) then
            local point = fb.map()
            point:set('attributes', source:get('attributes'))
            for _, key in ipairs({'time_unix_nano','start_time_unix_nano','flags'}) do
                local v = source:get(key); if v then point:set(key, v) end
            end
            if field == 'avg' then fb.set_metric_value(point, value:number() / count:number())
            elseif field == 'count' then fb.set_metric_value(point, value)
            else fb.set_metric_value(point, value:number()) end
            points:append(point)
        end
    end
    if points:len() == 0 then return nil end
    -- The derived family has a fresh number-datapoint model, preserving source context.
    local copy = metric:emit()
    copy.name = name or metric.name .. '.' .. field
    -- Distribution conversion is internal to this helper, never an implicit reinterpretation.
    fb._fts_number_metric(copy, points, field, metric.aggregation_temporality or 'cumulative')
    if field == 'count' then copy.unit = '1' end
    if monotonic ~= nil and field ~= 'avg' then copy.is_monotonic = monotonic end
    return copy
end

function fb._fts_number_metric(metric, points, field, temporality)
    local item = roots[metric]:get('item')
    for _, key in ipairs(kinds) do item:remove(key) end
    local data = fb.map(); data:set('data_points', points)
    if field == 'avg' then item:set('gauge', data)
    else
        data:set('aggregation_temporality', fb.int64(({unspecified=0,delta=1,cumulative=2})[temporality or 'cumulative']))
        data:set('is_monotonic', field == 'count')
        item:set('sum', data)
    end
end

local function unsigned_time(value)
    assert(value and (value:type() == 'uint64' or value:type() == 'int64'), 'time must be an integer')
    local text = value:value()
    assert(text:sub(1,1) ~= '-', 'time must be nonnegative')
    return text
end

local function after_or_equal(a, b)
    return #a > #b or (#a == #b and a >= b)
end

local function bucket_total(values)
    local total = fb.uint64(0)
    assert(values:type() == 'array', 'bucket counts must be an array')
    for i=1,values:len() do
        total = fb._fts_add(total, fb.uint64(unsigned_time(values:get(i))))
    end
    return total
end

local function valid_id(value, size, optional)
    assert(value and value:type() == 'bytes', 'ID must be bytes')
    local text = value:value()
    assert((optional and #text == 0) or (#text == size and not text:match('^%z+$')), 'invalid ID')
end

local function typed_identity(value)
    local kind, parts = value:type(), {}
    if kind == 'map' then
        local keys = value:keys(); table.sort(keys)
        for _, key in ipairs(keys) do
            local child = typed_identity(value:get(key))
            parts[#parts+1] = #key .. ':' .. key .. #child .. ':' .. child
        end
    elseif kind == 'array' then
        for i=1,value:len() do
            local child = typed_identity(value:get(i))
            parts[#parts+1] = #child .. ':' .. child
        end
    elseif kind == 'null' then
        return 'null'
    else
        local text = kind == 'double' and string.format('%.17g', value:number()) or tostring(value:value())
        if kind == 'int64' or kind == 'uint64' then kind = 'integer' end
        return kind .. ':' .. #text .. ':' .. text
    end
    return kind .. ':' .. table.concat(parts)
end

function fb._fts_validate_telemetry(root, signal, original)
    local item = root:get('item')
    assert(root:get('resource'):get('attributes'):type() == 'map', 'resource attributes must be a map')
    assert(root:get('scope'):get('attributes'):type() == 'map', 'scope attributes must be a map')
    local before = original and original:get("item")
    local function changed(key)
        local a, b = item:get(key), before and before:get(key)
        return not before or (a == nil) ~= (b == nil) or (a and not fb._fts_equal(a, b))
    end
    if signal == 'traces' then
        if changed("kind") then
            local kind = item:get_number("kind")
            assert(kind >= 0 and kind <= 5 and kind % 1 == 0, "invalid span kind")
        end
        if changed("status") then
            local status = item:get("status")
            local code = status and status:get_number("code") or 0
            assert(code >= 0 and code <= 2 and code % 1 == 0, "invalid span status")
        end
        for _, key in ipairs({'trace_id','span_id','parent_span_id'}) do
            if changed(key) then
            local value = item:get(key)
            assert(value and value:type() == 'bytes', 'span ID must be bytes internally')
            local text = value:value()
            assert((key == 'parent_span_id' and #text == 0) or
                (#text == (key == 'trace_id' and 16 or 8) and not text:match('^%z+$')), 'invalid span ID')
            end
        end
        if changed("end_time_unix_nano") or changed("start_time_unix_nano") then
        assert(after_or_equal(unsigned_time(item:get('end_time_unix_nano')),
            unsigned_time(item:get('start_time_unix_nano'))), 'span ends before it starts')
        end
        assert(item:get('attributes'):type() == 'map', 'span attributes must be a map')
        local events, links = item:get('events'), item:get('links')
        assert(events and events:type() == 'array' and links and links:type() == 'array',
            'span events and links must be arrays')
        for i=1,events:len() do
            local event = events:get(i)
            assert(event:get('attributes'):type() == 'map', 'event attributes must be a map')
            unsigned_time(event:get('time_unix_nano'))
        end
        for i=1,links:len() do
            local link = links:get(i)
            valid_id(link:get('trace_id'), 16, false); valid_id(link:get('span_id'), 8, false)
            assert(link:get('attributes'):type() == 'map', 'link attributes must be a map')
        end
    else
        local kind, data = metric_data(item)
        if changed('name') then
            assert(item:get_string('name') ~= '', 'metric name must not be empty')
        end
        local points = data:get('data_points')
        assert(points and points:type() == 'array', 'datapoints must be an array')
        local previous_kind, previous_data
        if before then previous_kind, previous_data = metric_data(before) end
        local previous_points = previous_data and previous_data:get('data_points')
        local layout, quantile_layout, identities = nil, nil, {}
        for i=1,points:len() do
            local point = points:get(i)
            local previous_point = previous_kind == kind and previous_points and previous_points:get(i)
            local point_changes = {}
            local function point_changed(key)
                if point_changes[key] ~= nil then return point_changes[key] end
                local a, b = point:get(key), previous_point and previous_point:get(key)
                local result = not previous_point or (a == nil) ~= (b == nil) or
                    (a ~= nil and not fb._fts_equal(a, b))
                point_changes[key] = result
                return result
            end
            local attrs = point:get('attributes')
            assert(attrs and attrs:type() == 'map', 'datapoint attributes must be a map')
            for _, key in ipairs(attrs:keys()) do
                assert(key ~= '' or (previous_point and
                    previous_point:get('attributes'):get(key)), 'metric attribute keys must not be empty')
            end
            local finish = unsigned_time(point:get('time_unix_nano'))
            local start = unsigned_time(point:get('start_time_unix_nano'))
            if point_changed('time_unix_nano') or point_changed('start_time_unix_nano') then
                assert(after_or_equal(finish, start), 'datapoint ends before it starts')
            end
            local keys = attrs:keys(); table.sort(keys)
            local identity = start .. ":" .. finish
            for _, key in ipairs(keys) do
                local value = typed_identity(attrs:get(key))
                identity = identity .. '|' .. #key .. ':' .. key .. #value .. ':' .. value
            end
            if point_changed('attributes') or point_changed('time_unix_nano') then
                assert(not identities[identity], 'duplicate series/window; aggregate explicitly')
            end
            identities[identity] = true
            if (kind == 'gauge' or kind == 'sum') and
                (point_changed('as_int') or point_changed('as_double') or
                 (kind == 'sum' and (not previous_data or not
                    fb._fts_equal(data:get('is_monotonic'), previous_data:get('is_monotonic'))))) then
                local integer, number = point:get('as_int'), point:get('as_double')
                assert((integer ~= nil) ~= (number ~= nil), 'scalar datapoint needs exactly one value')
                if kind == 'sum' and data:get('is_monotonic'):value() then
                    local value = integer or number
                    if value:type() == 'int64' then
                        assert(not value:value():match('^-'), 'monotonic sum cannot be negative')
                    elseif value:type() == 'double' then
                        assert(value:number() >= 0, 'monotonic sum cannot be negative')
                    end
                end
            end
            if kind == 'histogram' then
                local bounds, counts = point:get('explicit_bounds'), point:get('bucket_counts')
                assert(bounds and bounds:type() == 'array' and counts and counts:type() == 'array',
                    'histogram bounds and counts must be arrays')
                if point_changed('explicit_bounds') or point_changed('bucket_counts') or point_changed('count') then
                    assert(counts:len() == bounds:len()+1, 'histogram bucket layout mismatch')
                    assert(bucket_total(counts):value() == unsigned_time(point:get('count')), 'histogram count mismatch')
                end
                local previous, current = -math.huge, {}
                for j=1,bounds:len() do
                    local boundary = bounds:get(j):number()
                    if point_changed('explicit_bounds') then
                        assert(boundary > previous and boundary < math.huge, 'histogram bounds must increase')
                    end
                    previous = boundary; current[j] = boundary
                end
                if layout then
                    assert(#layout == #current, 'native histogram layouts must match')
                    for j=1,#layout do assert(layout[j] == current[j], 'native histogram layouts must match') end
                else layout = current end
            elseif kind == 'exponential_histogram' then
                local positive, negative = point:get('positive'), point:get('negative')
                local positive_counts = positive and positive:get('bucket_counts') or fb.array()
                local negative_counts = negative and negative:get('bucket_counts') or fb.array()
                assert(positive_counts:len() <= 65535 and negative_counts:len() <= 65535, 'too many exponential buckets')
                local total = fb._fts_add(bucket_total(positive_counts), bucket_total(negative_counts))
                total = fb._fts_add(total, fb.uint64(unsigned_time(point:get('zero_count'))))
                if point_changed('positive') or point_changed('negative') or
                    point_changed('zero_count') or point_changed('count') then
                    assert(total:value() == unsigned_time(point:get('count')), 'exponential histogram count mismatch')
                end
                local scale = point:get('scale'):number()
                if point_changed('scale') then
                    assert(scale >= -10 and scale <= 20, 'unsupported exponential scale')
                end
                if point_changed('zero_threshold') then
                    assert(point:get_number('zero_threshold') >= 0, 'negative zero threshold')
                end
            elseif kind == 'summary' then
                local quantiles = point:get('quantile_values')
                assert(quantiles and quantiles:type() == 'array', 'summary quantiles must be an array')
                local previous, current = -1, {}
                for j=1,quantiles:len() do
                    local quantile = quantiles:get(j):get_number('quantile')
                    if point_changed('quantile_values') then
                        assert(quantile >= 0 and quantile <= 1 and quantile > previous, 'invalid summary quantile')
                    end
                    previous = quantile; current[j] = quantile
                end
                if quantile_layout then
                    assert(#quantile_layout == #current, 'native summary layouts must match')
                    for j=1,#current do
                        assert(quantile_layout[j] == current[j], 'native summary layouts must match')
                    end
                else quantile_layout = current end
            end
        end
    end
end

local function clone(value)
    local holder = fb.map(); holder:set('value', value); return holder:get('value')
end

local function identity(point, keys)
    local attrs = point:get('attributes')
    if keys then fb.keep_keys(attrs, keys) end
    local names = attrs:keys(); table.sort(names)
    local parts = {unsigned_time(point:get('start_time_unix_nano')), unsigned_time(point:get('time_unix_nano'))}
    for _, key in ipairs(names) do
        local value = typed_identity(attrs:get(key))
        parts[#parts+1] = #key .. ':' .. key .. #value .. ':' .. value
    end
    return table.concat(parts, '|')
end

function fb.aggregate_metric(metric, keys, operation)
    operation = operation or 'sum'
    assert(metric.type == 'gauge' or metric.type == 'sum' or metric.type == 'histogram',
        'aggregation supports gauges, sums and explicit histograms')
    assert(operation == 'sum' or (metric.type == 'gauge' and
        (operation == 'min' or operation == 'max' or operation == 'mean' or operation == 'count')),
        'unsupported aggregation for this metric type')
    local groups, ordered = {}, {}
    for i=1,metric.datapoints:len() do
        local point = clone(metric.datapoints:get(i))
        local key = identity(point, keys)
        local state = groups[key]
        if not state then
            state = {point=point, count=1}; groups[key] = state; ordered[#ordered+1] = state
        else
            local target = state.point
            assert((point:get('flags') and point:get('flags'):value()) ==
                (target:get('flags') and target:get('flags'):value()), 'aggregation flags differ')
            state.count = state.count + 1
            if metric.type == 'histogram' then
                local bounds, old = point:get('explicit_bounds'), target:get('explicit_bounds')
                assert(bounds:len() == old:len(), 'histogram layouts differ')
                for j=1,bounds:len() do
                    assert(bounds:get(j):value() == old:get(j):value(), 'histogram layouts differ')
                end
                local buckets, previous = point:get('bucket_counts'), target:get('bucket_counts')
                for j=1,buckets:len() do previous:set(j, fb._fts_add(previous:get(j), buckets:get(j))) end
                target:set('count', fb._fts_add(target:get('count'), point:get('count')))
                if target:get('sum') and point:get('sum') then
                    target:set('sum', fb._fts_add(target:get('sum'), point:get('sum')))
                else target:remove('sum') end
                for _, bound in ipairs({'min','max'}) do
                    local a, b = target:get_number(bound), point:get_number(bound)
                    if a and b then target:set(bound, (bound == 'min' and math.min or math.max)(a,b))
                    else target:remove(bound) end
                end
            else
                local a, b = fb.metric_value(target), fb.metric_value(point)
                if operation == 'sum' or operation == 'mean' then
                    fb.set_metric_value(target, fb._fts_add(a,b))
                elseif operation == 'min' or operation == 'max' then
                    if (operation == 'min' and b:number() < a:number()) or
                        (operation == 'max' and b:number() > a:number()) then fb.set_metric_value(target,b) end
                end
            end
            local exemplars = point:get('exemplars')
            if exemplars then
                local target_exemplars = target:get('exemplars') or fb.array()
                for j=1,exemplars:len() do target_exemplars:append(exemplars:get(j)) end
                target:set('exemplars', target_exemplars)
            end
        end
    end
    local output = fb.array()
    for _, state in ipairs(ordered) do
        if operation == 'mean' then fb.set_metric_value(state.point, fb.metric_value(state.point):number() / state.count)
        elseif operation == 'count' then fb.set_metric_value(state.point, fb.int64(state.count)) end
        output:append(state.point)
    end
    metric.datapoints = output
    if operation == 'count' then metric.unit = '1' end
end

function fb.merge_histogram_buckets(metric, bounds)
    assert(metric.type == 'histogram', 'bucket merging requires an explicit histogram')
    if type(bounds) == 'userdata' then
        assert(bounds:type() == 'array', 'bounds must be an array')
        local values = {}
        for i=1,bounds:len() do values[i] = bounds:get(i):number() end
        bounds = values
    end
    assert(type(bounds) == 'table', 'bounds must be a numeric array')
    for i=2,#bounds do assert(bounds[i] > bounds[i-1], 'bounds must increase') end
    for i=1,metric.datapoints:len() do
        local point = metric.datapoints:get(i)
        local old, counts = point:get('explicit_bounds'), point:get('bucket_counts')
        local output, new_bounds = fb.array(), fb.array()
        local at, total = 1, fb.uint64(0)
        for _, boundary in ipairs(bounds) do
            local found = false
            while at <= old:len() and old:get(at):number() <= boundary do
                total = fb._fts_add(total, counts:get(at))
                if old:get(at):number() == boundary then found = true end
                at = at + 1
            end
            assert(found, 'new bounds must be a subset of existing bounds')
            new_bounds:append(boundary); output:append(total); total = fb.uint64(0)
        end
        while at <= counts:len() do total = fb._fts_add(total, counts:get(at)); at = at + 1 end
        output:append(total)
        point:set('explicit_bounds', new_bounds); point:set('bucket_counts', output)
    end
end
