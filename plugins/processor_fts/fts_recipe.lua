-- Embedded recipe registry. This module runs only in the private loader environment.
-- Block factories receive a separate read-only environment and parameter graph.
local fb = package.loaded.fluentbit
local registry = {}
local parameter_limits
local recipe_limits={steps=64,id_bytes=64}
local views = setmetatable({}, {__mode='k'})
local function immutable(value)
    if type(value) ~= 'table' then return value end
    local data, proxy = {}, {}
    for k,v in pairs(value) do data[k] = immutable(v) end
    views[proxy] = data
    return setmetatable(proxy, {__index=data, __newindex=function() error('immutable', 0) end,
        __metatable='FTS immutable value'})
end
local function iter(value) return next, views[value] or value, nil end
local function seq(value)
    local data = views[value] or value
    local function advance(_, i) i=i+1; if data[i] ~= nil then return i,data[i] end end
    return advance, nil, 0
end
local function length(value) return #(views[value] or value) end
local function mutable(value)
    if type(value)~='table' then return value end
    local result={}
    for key,child in iter(value) do result[key]=mutable(child) end
    return result
end
local active_mark,active_step,active_parameter
local function reject(reason,param)
    if active_mark then active_mark(active_step,'invalid_configuration',param or active_parameter or '<unknown>',reason) end
    error('invalid_parameter',0)
end
local function check(ok,reason,param) if not ok then reject(reason or 'type',param) end end
local function decimal(v)
    if type(v)=='table' and (v.type=='integer' or v.type=='double') then v=v.value end
    if type(v)=='number' then return v end
    if type(v)~='string' or #v>128 then return nil end
    local base,exponent=v:match('^([^eE]+)[eE]([+-]?%d+)$')
    base=base or v
    if not base:match('^[+-]?%d+%.?%d*$') and not base:match('^[+-]?%.%d+$') then return nil end
    return tonumber(v)
end
local function object(v, allowed)
    check(type(v)=='table')
    for k in pairs(v) do check(type(k)=='string' and allowed[k],'unknown','<unknown>') end
end
local function list(v, maximum)
    check(type(v)=='table' and #v<=maximum)
    local n=0
    for k in pairs(v) do check(type(k)=='number' and k>=1 and k<=#v and k%1==0); n=n+1 end
    check(n==#v)
end
local function strings(v)
    list(v,parameter_limits.string_items); check(#v>0)
    for _,x in ipairs(v) do check(type(x)=='string' and #x>0 and #x<=parameter_limits.string_bytes) end
end
local roots = {
    logs={body=true, metadata=true, attributes=true, ['resource.attributes']=true, ['scope.attributes']=true},
    metrics={},
    traces={attributes=true, events=true, links=true, ['resource.attributes']=true, ['scope.attributes']=true}
}
local selector_model={fields={root={type='selector_root',required=true},
    path={type='path',required=true}},max_path=32,max_segment_bytes=256,roots=roots}
local function selector(v, signal, context)
    object(v,selector_model.fields); check(roots[signal][v.root])
    list(v.path,selector_model.max_path)
    for _,k in ipairs(v.path) do check(type(k)=='string' and #k>0 and #k<=selector_model.max_segment_bytes) end
    -- User metadata is not the reserved OTel metadata namespace.
    if v.root=='metadata' then
        check(context=='native' and v.path[1]~='otlp','context')
    end
end
local function boolean(v) return v==true or v==false or v=='true' or v=='false' end
local literal_validate
-- Version 2 adds bounded recursive declarations; v1 keeps its original grammar.
local parameter_kinds={selector=true,selectors=true,strings=true,string=true,bool=true,
    number=true,bounds=true,map=true,list=true}
local recursive_kinds={object=true,array=true,literal=true}
parameter_limits={schema_depth=8,schema_nodes=1024,fields=128,
    value_depth=16,value_nodes=4096,array_items=128,string_items=128,string_bytes=256,selectors=16,bounds=256,identifier_bytes=64}
local function parameter_specifications(fields,version,depth,budget)
    check(depth<=parameter_limits.schema_depth,'depth','parameters')
    check(type(fields)=='table','type','parameters')
    local count=0
    for name,spec in pairs(fields) do
        count=count+1;budget.n=budget.n+1
        check(version==1 or (count<=parameter_limits.fields and budget.n<=parameter_limits.schema_nodes),'range','parameters')
        check(type(name)=='string' and #name<=64 and name:match('^[a-z][a-z0-9_]*$'),'type','parameters')
        object(spec,version==1 and {type=true,required=true,default=true,enum=true} or
            {type=true,required=true,default=true,enum=true,fields=true,items=true,minimum=true,maximum=true,integer=true})
        check(parameter_kinds[spec.type] or (version==2 and recursive_kinds[spec.type]),'type','parameters')
        check(spec.required==nil or type(spec.required)=='boolean','type','required')
        if spec.enum ~= nil then
            check(version==1 or spec.type=='string','type','enum')
            strings(spec.enum)
            local allowed={}
            for _,entry in ipairs(spec.enum) do allowed[entry]=true end
            spec.enum=allowed
        end
        if version==2 then
            for _,bound in ipairs({'minimum','maximum'}) do
                if spec[bound]~=nil then
                    check(spec.type=='number','type',bound)
                    local number=decimal(spec[bound])
                    check(number and number==number and number~=math.huge and number~=-math.huge,'range',bound)
                    spec[bound]=number
                end
            end
            check(spec.integer==nil or (spec.type=='number' and type(spec.integer)=='boolean'),'type','integer')
            check(spec.minimum==nil or spec.maximum==nil or spec.minimum<=spec.maximum,'range','parameters')
            if spec.type=='object' then
                check(spec.items==nil and spec.fields~=nil,'type','fields')
                parameter_specifications(spec.fields,version,depth+1,budget)
            elseif spec.type=='array' then
                check(spec.fields==nil and spec.items~=nil,'type','items')
                parameter_specifications({item=spec.items},version,depth+1,budget)
                check(spec.items.required==nil and spec.items.default==nil,'type','items')
            else check(spec.fields==nil and spec.items==nil,'unknown','parameters') end
        end
    end
end

local function schema(params, fields, signal, context, depth, budget)
    depth=depth or 0;budget=budget or {n=0}
    check(depth<=parameter_limits.value_depth,'depth','parameters')
    object(params,fields)
    for name,spec in pairs(fields) do
        budget.n=budget.n+1
        check(depth==0 or budget.n<=parameter_limits.value_nodes,'range','parameters')
        active_parameter=name
        local v=params[name]
        if v==nil then
            check(not spec.required,'missing',name)
            if spec.default~=nil then params[name]=mutable(spec.default); v=params[name] end
        end
        if v~=nil then
            local t=spec.type
            if t=='selector' then selector(v,signal,context)
            elseif t=='severity_destination' then
                if v=='otel' then check(context=='otel','context',name)
                else selector(v,signal,context) end
            elseif t=='list' then list(v,parameter_limits.array_items)
            elseif t=='selectors' then list(v,parameter_limits.selectors); check(#v>0); for _,x in ipairs(v) do selector(x,signal,context) end
            elseif t=='strings' then strings(v)
            elseif t=='string' then check(type(v)=='string' and #v<=parameter_limits.string_bytes)
            elseif t=='bool' then check(boolean(v)); params[name]=(v==true or v=='true')
            elseif t=='number' then
                v=decimal(v); check(v~=nil,'type'); check(v==v and v~=math.huge and v~=-math.huge,'range'); params[name]=v
            elseif t=='bounds' then
                list(v,parameter_limits.bounds); local previous=-math.huge
                for i,x in ipairs(v) do x=decimal(x); check(x and x>previous and x<math.huge,'range'); v[i]=x;previous=x end
            elseif t=='map' then check(type(v)=='table')
            elseif t=='object' then schema(v,spec.fields,signal,context,depth+1,budget)
            elseif t=='array' then
                list(v,parameter_limits.array_items)
                for i,item in ipairs(v) do
                    local holder={item=item}
                    schema(holder,{item=spec.items},signal,context,depth+1,budget)
                    v[i]=holder.item
                end
            elseif t=='literal' then literal_validate(v,0,{n=0})
            end
            if t=='number' then
                if spec.minimum then check(params[name]>=spec.minimum,'range',name) end
                if spec.maximum then check(params[name]<=spec.maximum,'range',name) end
                if spec.integer then
                    check(params[name]==math.floor(params[name]) and math.abs(params[name])<=9007199254740991,'range',name)
                end
                if spec.exclusive_minimum then check(params[name]>spec.exclusive_minimum,'range',name) end
            end
            if spec.enum then check(spec.enum[params[name]]) end
        end
    end
end
local function root(item, s)
    if s.root=='resource.attributes' then return item.resource and item.resource.attributes end
    if s.root=='scope.attributes' then return item.scope and item.scope.attributes end
    return item[s.root]
end
local function value(item,s)
    local v=root(item,s)
    for _,k in seq(s.path) do
        if not v then return nil end
        if v:type()~='map' then error('wrong_type',0) end
        v=v:get(k)
    end
    return v
end
local function parent(item,s)
    local v=root(item,s)
    local n=length(s.path)
    if n==0 then error('invalid_parameter',0) end
    for i=1,n-1 do
        if not v or v:type()~='map' then error('wrong_type',0) end
        v=v:get(s.path[i])
    end
    if not v or v:type()~='map' then error('wrong_type',0) end
    return v,s.path[n]
end
local function selected(names,name)
    for _,n in seq(names) do if n==name then return true end end
    return false
end
local active_metric_projection
local helpers = {value=value,parent=parent,root=root,selected=selected,length=length}
local function add(id, signals, fields, source, validate, privacy)
    registry[id]={signals=signals,parameters=fields,source=source,validate=validate,privacy=privacy or false}
end
add('shared.redact_keys',{logs=true,traces=true}, {
    targets={type='selectors',required=true},keys={type='strings',required=true},
    replacement={type='string',default='[REDACTED]'}}, [[
return function(p)
    local keys={}
    for _,key in ipairs(p.keys) do keys[#keys+1]=key end
    return function(item)
        for _,s in ipairs(p.targets) do
            local v=h.value(item,s)
            if v then
                if v:type()~='map' and v:type()~='array' then error('wrong_type') end
                if s.root=='events' or s.root=='links' then
                    if v:type()~='array' then error('wrong_type') end
                    for i=1,v:len() do
                        local entry=v:get(i)
                        if entry:type()~='map' then error('wrong_type') end
                        local attrs=entry:get('attributes')
                        if attrs then
                            if attrs:type()~='map' then error('wrong_type') end
                            local before=attrs:len()
                            fb.redact(attrs,keys,p.replacement)
                            h.dropped_map(entry,before-attrs:len())
                        end
                    end
                else
                    local before=v:len()
                    fb.redact(v,keys,p.replacement)
                    if h.length(s.path)==0 then h.dropped(item,s,before-v:len()) end
                end
            end
        end
    end
end
]],function(p)
    for _,s in ipairs(p.targets) do
        if s.root=='events' or s.root=='links' then check(#s.path==0,'range','targets') end
    end
end,true)
add('metrics.scale',{metrics=true},{names={type='strings',required=true},
    input_unit={type='string',required=true},output_unit={type='string',required=true},
    factor={type='number',required=true}, numeric_policy={type='string',default='preserve_integer',
        enum={preserve_integer=true,allow_double=true}}}, [[
return function(p)
    return function(item)
        if not h.selected(p.names,item.name) then return end
        if item.unit~=p.input_unit then error('wrong_type') end
        if p.numeric_policy=='preserve_integer' and p.factor~=math.floor(p.factor) then
            for i=1,item.datapoints:len() do
                local v=fb.metric_value(item.datapoints:get(i))
                if v and v:type()=='int64' then error('unsupported_conversion') end
                local exemplars=item.datapoints:get(i):get('exemplars')
                if exemplars then
                    for j=1,exemplars:len() do
                        local e=fb.metric_value(exemplars:get(j))
                        if e and e:type()=='int64' then error('unsupported_conversion') end
                    end
                end
            end
        end
        fb.scale_metric(item,p.factor,p.output_unit)
    end
end
]])
add('metrics.merge_histogram_buckets',{metrics=true}, {
    names={type='strings',required=true},bounds={type='bounds',required=true}}, [[
return function(p)
    local bounds=fb.array()
    for _,b in ipairs(p.bounds) do bounds:append(b) end
    return function(item)
        if h.selected(p.names,item.name) then fb.merge_histogram_buckets(item,bounds) end
    end
end
]])
local function overlap(a,b)
    if a.root~=b.root then return false end
    for i=1,math.min(#a.path,#b.path) do if a.path[i]~=b.path[i] then return false end end
    return true
end
local literal_model={fields={type={type='literal_kind',required=true},value={type='literal_value'}},
    max_depth=16,max_nodes=1024,max_items=1024,max_string_bytes=65536}
literal_validate=function(v,depth,budget)
    budget.n=budget.n+1;check(depth<=literal_model.max_depth and budget.n<=literal_model.max_nodes,'range','value')
    if type(v)=='string' then check(#v<=literal_model.max_string_bytes,'range','value');return end
    if type(v)=='boolean' then return end
    object(v,literal_model.fields)
    local kind=v.type
    if kind=='null' then check(v.value==nil);return end
    if (kind=='integer' or kind=='int64' or kind=='uint64' or kind=='double') and type(v.value)=='table'
        and (v.value.type=='integer' or v.value.type=='double') then v.value=v.value.value end
    check(v.value~=nil,'missing','value')
    if kind=='string' then check(type(v.value)=='string' and #v.value<=literal_model.max_string_bytes)
    elseif kind=='bool' then check(type(v.value)=='boolean')
    elseif kind=='integer' or kind=='int64' or kind=='uint64' then
        if type(v.value)=='string' then
            check(v.value:match(kind~='uint64' and '^%-?%d+$' or '^%d+$')~=nil)
        else check(type(v.value)=='number' and v.value%1==0) end
        local signed=kind=='int64' or (kind=='integer' and tostring(v.value):sub(1,1)=='-')
        local ok=pcall(signed and fb.int64 or fb.uint64,v.value)
        check(ok,'range','value')
    elseif kind=='double' then
        local n=decimal(v.value);check(n and n==n and n<math.huge and n>-math.huge,'range','value')
    elseif kind=='bytes' then
        check(type(v.value)=='string' and #v.value<=literal_model.max_string_bytes and #v.value%2==0 and not v.value:find('[^%x]'))
    elseif kind=='array' then
        list(v.value,literal_model.max_items);for _,child in ipairs(v.value) do literal_validate(child,depth+1,budget) end
    elseif kind=='map' then
        check(type(v.value)=='table')
        for key,child in pairs(v.value) do
            check(type(key)=='string' and #key<=256);literal_validate(child,depth+1,budget)
        end
    else reject('type','value') end
end
local function literal(v)
    if type(v)~='table' then return v end
    local kind=v.type
    if kind=='null' then return fb.null end
    if kind=='string' or kind=='bool' then return v.value end
    if kind=='integer' then
        return (tostring(v.value):sub(1,1)=='-' and fb.int64 or fb.uint64)(v.value)
    end
    if kind=='int64' then return fb.int64(v.value) end
    if kind=='uint64' then return fb.uint64(v.value) end
    if kind=='double' then return decimal(v.value) end
    if kind=='bytes' then
        return fb.bytes((v.value:gsub('..',function(pair) return string.char(tonumber(pair,16)) end)))
    end
    local result=kind=='array' and fb.array() or fb.map()
    if kind=='array' then for _,child in seq(v.value) do result:append(literal(child)) end
    else
        local keys={}
        for key in iter(v.value) do keys[#keys+1]=key end
        table.sort(keys)
        for _,key in ipairs(keys) do result:set(key,literal(v.value[key])) end
    end
    return result
end
-- Materialize validated configuration literals as native typed values.
function fb.literal(value)
    literal_validate(value,0,{n=0})
    return literal(value)
end
local function dropped(item,selector,count)
    if count==0 or (selector.root~='attributes' and selector.root~='resource.attributes'
        and selector.root~='scope.attributes') then return end
    if item.signal=='traces' then
        local owner=item
        if selector.root=='resource.attributes' then owner=item.resource end
        if selector.root=='scope.attributes' then owner=item.scope end
        local previous=owner.dropped_attributes_count or 0
        if previous+count>4294967295 then error('unsupported_conversion',0) end
        owner.dropped_attributes_count=previous+count
    elseif fb.is_otel(item) then
        local owner
        if selector.root=='attributes' then owner=item.metadata:ensure_map('otlp')
        else owner=item.context.attributes:get(selector.root:match('^(%w+)%.')) end
        if not owner or owner:type()~='map' then error('invalid_context',0) end
        local previous=owner:get('dropped_attributes_count')
        previous=previous and previous:number() or 0
        if previous+count>4294967295 then error('unsupported_conversion',0) end
        owner:set('dropped_attributes_count',fb.uint64(previous+count))
    end
end
helpers.metric_name_exists=function(name) return fb._recipe_metric_name_exists(name,active_metric_projection) end
helpers.dropped_map=function(owner,count)
    if count==0 then return end
    local previous=owner:get('dropped_attributes_count')
    if previous and previous:type()~='int64' and previous:type()~='uint64' then error('invalid_context',0) end
    previous=previous and previous:number() or 0
    if previous+count>4294967295 then error('unsupported_conversion',0) end
    owner:set('dropped_attributes_count',fb.uint64(previous+count))
end
helpers.parse_json=function(text)
    local ok,result=pcall(fb.parse_json,text)
    if not ok then
        local message=type(result)=='string' and (result:match('^.-:%d+: (.*)$') or result)
        if message=='not enough memory' or message=='Lua policy memory limit exceeded'
            or message=='JSON value exceeds policy memory or nesting limit' then error('budget_exceeded',0) end
        error('invalid_json',0)
    end
    return result
end
helpers.literal=literal
helpers.dropped=dropped
helpers.name_match=function(rule,name)
    if rule.names and selected(rule.names,name) then return true end
    if rule.prefixes then
        for _,prefix in seq(rule.prefixes) do if name:sub(1,#prefix)==prefix then return true end end
    end
    return false
end

add('logs.parse_json',{logs=true},{source={type='selector',required=true},
    destination={type='selector',required=true},remove_source={type='bool',default=false},
    on_missing={type='string',default='error',enum={skip=true,error=true}},
    collision={type='string',default='error',enum={error=true,overwrite=true,preserve_destination=true}}}, [[
return function(p)
    return function(item)
        local source=h.value(item,p.source)
        if not source then if p.on_missing=='skip' then return end;error('missing_field') end
        if source:type()~='string' then error('wrong_type') end
        local destination,key=h.parent(item,p.destination)
        if destination:get(key) then
            if p.collision=='preserve_destination' then return end
            if p.collision=='error' then error('collision') end
        end
        local parsed=h.parse_json(source:value())
        if parsed:type()~='map' then error('wrong_type') end
        destination:set(key,parsed)
        if p.remove_source then local owner,name=h.parent(item,p.source);owner:remove(name) end
    end
end
]],function(p)
    check(#p.destination.path>0 and #p.source.path>0,'range')
    check(not overlap(p.source,p.destination),'range','destination')
    check(not p.remove_source or p.collision~='preserve_destination','range','collision')
end)

add('logs.normalize_severity',{logs=true},{source={type='selector',required=true},
    destination={type='severity_destination',required=true},
    profile={type='string',default='common',enum={common=true}},overwrite={type='bool',default=false},
    on_missing={type='string',default='skip',enum={skip=true,error=true}},
    on_unknown={type='string',default='preserve',enum={preserve=true,error=true}}}, [[
return function(p)
    local names={trace='TRACE',debug='DEBUG',info='INFO',information='INFO',informational='INFO',
        warn='WARN',warning='WARN',error='ERROR',fatal='FATAL',critical='FATAL',
        dbg='DEBUG',notice='INFO',err='ERROR',crit='FATAL',alert='FATAL',emerg='FATAL'}
    return function(item)
        local source=h.value(item,p.source)
        if not source then if p.on_missing=='skip' then return end;error('missing_field') end
        if source:type()~='string' then error('wrong_type') end
        local level=names[source:value():match('^%s*(.-)%s*$'):lower()]
        if not level then if p.on_unknown=='preserve' then return end;error('wrong_type') end
        if p.destination=='otel' then
            if not fb.is_otel(item) then error('invalid_context') end
            local number=fb.log_field(item,'severity_number')
            if not p.overwrite and (fb.log_field(item,'severity_text') or (number and number:number()~=0)) then return end
            fb.set_severity(item,level)
        else
            local owner,key=h.parent(item,p.destination)
            if p.overwrite or not owner:get(key) then owner:set(key,level) end
        end
    end
end
]],function(p)
    if type(p.destination)=='table' then
        check(#p.destination.path>0,'range','destination')
        if overlap(p.source,p.destination) and #p.source.path==#p.destination.path then p.overwrite=true end
    end
end)

local operation_parameters={}
for _,op in ipairs({'set','set_default','copy','rename','keep','remove'}) do
    local fields={op={type='string',required=true,enum={[op]=true}},
        target={type='selector',required=true}}
    if op=='set' or op=='set_default' then fields.value={type='literal',required=true}
    elseif op=='copy' or op=='rename' then
        fields.source={type='selector',required=true}
        fields.collision={type='string',default='error',
            enum={error=true,overwrite=true,preserve_destination=true}}
        fields.on_missing={type='string',default='skip',enum={skip=true,error=true}}
    else fields.names={type='strings'};fields.prefixes={type='strings'} end
    operation_parameters[op]=fields
end
add('fields.edit',{logs=true,traces=true},{operations={type='list',required=true}}, [[
return function(p)
    return function(item)
        for _,op in ipairs(p.operations) do
            if op.op=='keep' or (op.op=='remove' and (op.names or op.prefixes)) then
                local target=h.value(item,op.target)
                if not target or target:type()~='map' then error('wrong_type') end
                local before=target:len()
                for _,key in ipairs(target:keys()) do
                    local matches=h.name_match(op,key)
                    if (op.op=='keep' and not matches) or (op.op=='remove' and matches) then target:remove(key) end
                end
                if h.length(op.target.path)==0 then h.dropped(item,op.target,before-target:len()) end
            else
                local owner,key=h.parent(item,op.target)
                local old=owner:get(key)
                if op.op=='remove' then
                    local before=owner:len();owner:remove(key)
                    if h.length(op.target.path)==1 then h.dropped(item,op.target,before-owner:len()) end
                elseif op.op=='set' or op.op=='set_default' then
                    if op.op=='set' or not old then owner:set(key,h.literal(op.value)) end
                else
                    local source=h.value(item,op.source)
                    if source then
                        if not old or op.collision=='overwrite' then
                            owner:set(key,source)
                            if op.op=='rename' then local from,name=h.parent(item,op.source);from:remove(name) end
                        elseif op.collision~='preserve_destination' then error('collision') end
                    elseif op.on_missing=='error' then error('missing_field') end
                end
            end
        end
    end
end
]],function(p,signal,context)
    check(#p.operations>0,'range','operations')
    for _,op in ipairs(p.operations) do
        check(type(op)=='table','type','operations')
        local fields=operation_parameters[op.op]
        check(fields~=nil,'type','op')
        object(op,fields);selector(op.target,signal,context)
        check(op.target.root~='events' and op.target.root~='links','context','target')
        if op.op=='keep' or (op.op=='remove' and (op.names or op.prefixes)) then
            check(op.names~=nil or op.prefixes~=nil,'missing','names')
            if op.names then strings(op.names) end;if op.prefixes then strings(op.prefixes) end
        else check(#op.target.path>0,'range','target') end
        if fields.value then literal_validate(op.value,0,{n=0}) end
        if fields.source then
            selector(op.source,signal,context)
            check(not overlap(op.source,op.target),'range','source')
            check(op.op~='rename' or #op.source.path>0,'range','source')
            op.collision=op.collision or fields.collision.default;op.on_missing=op.on_missing or fields.on_missing.default
            check(fields.collision.enum[op.collision],'type','collision')
            check(fields.on_missing.enum[op.on_missing],'type','on_missing')
        end
    end
end)

local name_filter_parameters={names={type='strings'},prefixes={type='strings'}}
add('metrics.select',{metrics=true},{keep={type='map'},drop={type='map'}}, [[
return function(p)
    return function(item)
        if p.keep and not h.name_match(p.keep,item.name) then return fb.DROP end
        if p.drop and h.name_match(p.drop,item.name) then return fb.DROP end
    end
end
]],function(p)
    check((p.keep~=nil)~=(p.drop~=nil),'type','keep')
    local rule=p.keep or p.drop;object(rule,name_filter_parameters)
    check(rule.names~=nil or rule.prefixes~=nil,'missing','names')
    if rule.names then strings(rule.names) end;if rule.prefixes then strings(rule.prefixes) end
end)

add('metrics.rename',{metrics=true},{mapping={type='map',required=true}}, [[
return function(p)
    return function(item)
        local name=p.mapping[item.name]
        if name and name~=item.name then
            if h.metric_name_exists(name) then error('collision') end
            item.name=name
        end
    end
end
]],function(p)
    local targets,n={},0
    for source,target in pairs(p.mapping) do
        n=n+1;check(type(source)=='string' and #source>0 and #source<=256)
        check(type(target)=='string' and #target>0 and #target<=256)
        check(not targets[target],'duplicate','mapping');targets[target]=source
        local seen,current={},source
        while p.mapping[current] and p.mapping[current]~=current do
            check(not seen[current],'range','mapping');seen[current]=true;current=p.mapping[current]
        end
    end
    check(n>0 and n<=128,'range','mapping')
    for source,target in pairs(p.mapping) do
        check(source==target or not p.mapping[target],'chain','mapping')
    end
end)

add('traces.name_from_route',{traces=true},{
    method_attribute={type='string',default='http.request.method'},
    route_attribute={type='string',default='http.route'},
    on_missing={type='string',default='preserve',enum={preserve=true,error=true}}}, [[
return function(p)
    local methods={CONNECT=true,DELETE=true,GET=true,HEAD=true,OPTIONS=true,PATCH=true,POST=true,PUT=true,TRACE=true}
    return function(item)
        if item.kind~=2 then return end
        local route=item.attributes:get(p.route_attribute)
        if not route then if p.on_missing=='preserve' then return end;error('missing_field') end
        if route:type()~='string' then error('wrong_type') end
        local method=item.attributes:get(p.method_attribute)
        if method and method:type()~='string' then error('wrong_type') end
        method=method and method:value():upper() or 'HTTP'
        if not methods[method] then method='HTTP' end
        local name=method..' '..route:value()
        if #name>1024 then return end
        item.name=name
    end
end
]])

local scalar_types={integer=true,string=true,bool=true,int64=true,uint64=true,double=true,bytes=true,['null']=true}
local numeric_types={integer=true,int64=true,uint64=true,double=true}
local function scalar_literal(v)
    literal_validate(v,0,{n=0})
    check(type(v)~='table' or scalar_types[v.type],'type','value')
end
local condition_operators={eq=true,neq=true,['in']=true,not_in=true,gt=true,gte=true,lt=true,lte=true}
local condition_model={fields={all={type='conditions'},any={type='conditions'},
    selector={type='selector'},op={type='string',enum=condition_operators},
    value={type='scalar_literal'},values={type='scalar_literals'}},max_depth=8,max_nodes=128,max_items=128}
local function condition_validate(c,signal,context,depth,budget)
    depth=depth or 0;budget=budget or {n=0};budget.n=budget.n+1
    check(depth<=condition_model.max_depth and budget.n<=condition_model.max_nodes,'range','condition')
    object(c,condition_model.fields)
    if c.all or c.any then
        check((c.all~=nil)~=(c.any~=nil))
        check(c.selector==nil and c.op==nil and c.value==nil and c.values==nil)
        local children=c.all or c.any;list(children,condition_model.max_items);check(#children>0,'range','condition')
        for _,child in ipairs(children) do condition_validate(child,signal,context,depth+1,budget) end
    else
        selector(c.selector,signal,context)
        check(c.selector.root~='events' and c.selector.root~='links','range','selector')
        check(condition_operators[c.op])
        if c.op=='in' or c.op=='not_in' then
            check(c.value==nil);list(c.values,condition_model.max_items);check(#c.values>0)
            local expected
            for _,v in ipairs(c.values) do
                scalar_literal(v)
                local kind=type(v)=='table' and v.type or (type(v)=='boolean' and 'bool' or 'string')
                check(not expected or expected==kind or (numeric_types[expected] and numeric_types[kind]),'type','values');expected=kind
            end
        else
            check(c.values==nil and c.value~=nil);scalar_literal(c.value)
            if c.op~='eq' and c.op~='neq' then
                check(type(c.value)=='table' and numeric_types[c.value.type],'type','value')
            end
        end
    end
end
local function condition_value(item,s)
    local v=root(item,s)
    for _,key in seq(s.path) do
        if not v or v:type()~='map' then return nil end
        v=v:get(key)
    end
    return v
end
-- Decimal integer ordering avoids passing int64/uint64 through lua_Number.
local function integer_compare(a,b)
    local negative_a,negative_b=a:sub(1,1)=='-',b:sub(1,1)=='-'
    if negative_a~=negative_b then return negative_a and -1 or 1 end
    if negative_a then a=a:sub(2);b=b:sub(2) end
    local result=0
    if #a~=#b then result=#a<#b and -1 or 1
    elseif a~=b then result=a<b and -1 or 1 end
    return negative_a and -result or result
end
local function compare_values(a,b)
    local ak,bk=a:type(),b:type()
    if numeric_types[ak] and numeric_types[bk] then
        if ak~='double' and bk~='double' then return integer_compare(a:value(),b:value()) end
        local function finite(x) return x==x and x~=math.huge and x~=-math.huge end
        if ak=='double' and bk=='double' then
            local x,y=a:value(),b:value()
            if not finite(x) or not finite(y) then return nil end
            return x==y and 0 or (x<y and -1 or 1)
        end
        local integer,number=a,b:value()
        local invert=ak=='double'
        if invert then integer,number=b,a:value() end
        if not finite(number) then return nil end
        local floor=math.floor(number)
        -- %.0f prints the represented integral double, not a rounded integer operand.
        local text=floor==0 and '0' or string.format('%.0f',floor)
        local result=integer_compare(integer:value(),text)
        if result==0 and number~=floor then result=-1 end
        return invert and -result or result
    end
    if ak~=bk then return nil end
    return a:value()==b:value() and 0 or 1
end
helpers.compare_values=compare_values
fb.numeric_compare=compare_values
helpers.matches_type=function(v,kind)
    return v:type()==kind or (kind=='integer' and (v:type()=='int64' or v:type()=='uint64'))
end
local function prepare_condition(c)
    if c.all or c.any then
        local children={}
        for _,child in seq(c.all or c.any) do children[#children+1]=prepare_condition(child) end
        return function(item)
            for _,child in ipairs(children) do
                local matched=child(item)
                if c.all and not matched then return false end
                if c.any and matched then return true end
            end
            return c.all~=nil
        end
    end
    local expected={}
    local function add_expected(v)
        local holder=fb.map();holder:set('v',literal(v));expected[#expected+1]=holder:get('v')
    end
    if c.values then for _,v in seq(c.values) do add_expected(v) end else add_expected(c.value) end
    return function(item)
        local actual=condition_value(item,c.selector)
        if not actual then return false end
        local comparison=compare_values(actual,expected[1])
        if comparison==nil then return false end
        if c.op=='gt' or c.op=='gte' or c.op=='lt' or c.op=='lte' then
            if c.op=='gt' then return comparison>0 elseif c.op=='gte' then return comparison>=0
            elseif c.op=='lt' then return comparison<0 else return comparison<=0 end
        end
        local matched=false
        for _,v in ipairs(expected) do if compare_values(actual,v)==0 then matched=true;break end end
        if c.op=='neq' or c.op=='not_in' then return not matched end
        return matched
    end
end
helpers.prepare_condition=prepare_condition
helpers.truncate_utf8=function(text,limit) return fb._recipe_truncate_utf8(text,limit) end
helpers.parse_timestamp=function(text)
    local ok,result=pcall(fb.parse_time,text)
    if not ok then
        local message=type(result)=='string' and (result:match('^.-:%d+: (.*)$') or result)
        if message=='not enough memory' then error('budget_exceeded',0) end
        error('invalid_timestamp',0)
    end
    return result
end

add('logs.parse_timestamp',{logs=true},{source={type='selector',required=true},
    on_missing={type='string',default='error',enum={skip=true,error=true}}}, [[
return function(p)
    return function(item)
        local source=h.value(item,p.source)
        if not source then if p.on_missing=='skip' then return end;error('missing_field') end
        if source:type()~='string' then error('wrong_type') end
        item.timestamp=h.parse_timestamp(source:value())
    end
end
]])
add('logs.drop_matching',{logs=true},{condition={type='map',required=true}}, [[
return function(p)
    local matches=h.prepare_condition(p.condition)
    return function(item) if matches(item) then return fb.DROP end end
end
]],function(p,signal,context) condition_validate(p.condition,signal,context) end)

local field_rule_parameters={selector={type='selector',required=true},
    required={type='bool',default=true},type={type='field_kind',required=true},
    enum={type='scalar_literals'}}
add('logs.validate_fields',{logs=true},{rules={type='list',required=true}}, [[
return function(p)
    local enums={}
    for i,rule in ipairs(p.rules) do
        if rule.enum then
            local values=fb.array()
            for _,v in ipairs(rule.enum) do values:append(h.literal(v)) end
            enums[i]=values
        end
    end
    return function(item)
        for i,rule in ipairs(p.rules) do
            local v=h.value(item,rule.selector)
            if not v then
                if rule.required then error('validation_failed') end
            else
                if not h.matches_type(v,rule.type) then error('validation_failed') end
                if enums[i] then
                    local found=false
                    for j=1,enums[i]:len() do
                        local candidate=enums[i]:get(j)
                        if h.compare_values(candidate,v)==0 then found=true;break end
                    end
                    if not found then error('validation_failed') end
                end
            end
        end
    end
end
]],function(p,signal,context)
    check(#p.rules>0,'range','rules')
    for _,rule in ipairs(p.rules) do
        object(rule,field_rule_parameters)
        selector(rule.selector,signal,context)
        check(scalar_types[rule.type] or rule.type=='array' or rule.type=='map','type','type')
        if rule.required==nil then rule.required=field_rule_parameters.required.default end
        check(type(rule.required)=='boolean','type','required')
        if rule.enum then
            check(scalar_types[rule.type]);list(rule.enum,128);check(#rule.enum>0)
            for _,v in ipairs(rule.enum) do
                scalar_literal(v)
                local kind=type(v)=='table' and v.type or (type(v)=='boolean' and 'bool' or 'string')
                check(kind==rule.type or (numeric_types[kind] and numeric_types[rule.type]),'type','enum')
            end
        end
    end
end)
add('fields.truncate',{logs=true,traces=true},{target={type='selector',required=true},
    max_bytes={type='number',required=true},marker={type='selector',required=true},
    collision={type='string',default='error',enum={error=true,overwrite=true}},
    on_missing={type='string',default='skip',enum={skip=true,error=true}}}, [[
return function(p)
    return function(item)
        local v=h.value(item,p.target)
        if not v then if p.on_missing=='skip' then return end;error('missing_field') end
        if v:type()~='string' then error('wrong_type') end
        local text,changed=h.truncate_utf8(v:value(),p.max_bytes)
        if not changed then return end
        local owner,key=h.parent(item,p.marker)
        local previous=owner:get(key)
        if previous and p.collision=='error' then error('collision') end
        owner:set(key,true)
        owner,key=h.parent(item,p.target);owner:set(key,text)
    end
end
]],function(p)
    check(#p.target.path>0 and #p.marker.path>0,'range','target')
    check(p.target.root~='events' and p.target.root~='links','range','target')
    check(p.marker.root~='events' and p.marker.root~='links','range','marker')
    check(not overlap(p.target,p.marker),'range','marker')
end)

add('metrics.aggregate_dimensions',{metrics=true},{names={type='strings',required=true},
    keep_attributes={type='list',default={}},operation={type='string',required=true,
        enum={sum=true,min=true,max=true,mean=true,count=true}},
    max_exemplars={type='number',default=0}}, [[
return function(p)
    local keys={}
    for _,key in ipairs(p.keep_attributes) do keys[#keys+1]=key end
    return function(item)
        if not h.selected(p.names,item.name) then return end
        if item.type~='gauge' and item.type~='sum' and item.type~='histogram' then error('wrong_type') end
        if item.type~='gauge' and p.operation~='sum' then error('invalid_parameter') end
        fb.aggregate_metric(item,keys,p.operation,p.max_exemplars)
    end
end
]],function(p)
    for _,key in ipairs(p.keep_attributes) do check(type(key)=='string' and #key>0 and #key<=256,'type','keep_attributes') end
end)

-- Native decisions own mutable state; block closures retain only constants.
local function state_parameters(throttle)
    local fields={keys={type='selectors',required=true},tenant={type='selector'},
        ttl_ms={type='number',required=true},max_keys={type='number',default=1024},
        max_key_bytes={type='number',default=1024},
        overflow={type='string',default='keep',enum={keep=true}},
        on_missing={type='string',default='error',enum={keep=true,error=true}}}
    if throttle then
        fields.rate={type='number',required=true}
        fields.burst={type='number',required=true}
    end
    return fields
end
local function state_validate(p)
    if p.rate then check(p.ttl_ms*p.rate>=p.burst*1000,'refill_horizon','ttl_ms') end
end
helpers.state_key=function(item,p)
    local key,oversized='',false
    local function append(selector)
        local v=value(item,selector)
        if not v then
            if p.on_missing=='keep' then return false end
            error('missing_field',0)
        end
        local kind=v:type()
        if kind=='map' or kind=='array' then error('wrong_type',0) end
        local text=v:value()
        if kind=='int64' or kind=='uint64' then kind='integer'
        elseif kind=='double' then
            if text~=text or text==math.huge or text==-math.huge then error('wrong_type',0) end
            text=text==0 and '0' or string.format('%.17g',text)
        elseif kind=='null' then text=''
        elseif kind=='bool' then text=text and '1' or '0'
        elseif kind~='string' and kind~='bytes' then error('wrong_type',0) end
        if #key+#kind+#text+32>p.max_key_bytes+32 then oversized=true end
        if not oversized then key=key..#kind..':'..kind..#text..':'..text end
        return true
    end
    if p.tenant and not append(p.tenant) then return nil end
    for _,selector in seq(p.keys) do if not append(selector) then return nil end end
    if oversized then return string.rep('x',p.max_key_bytes+1) end
    return key
end
helpers.state_decide=function(key) return fb._recipe_state_decide(key) end
local state_source=[[return function(p)
    return function(item)
        local key=h.state_key(item,p)
        if key and h.state_decide(key) then return fb.DROP end
    end
end]]
add('logs.dedupe',{logs=true},state_parameters(false),state_source,state_validate)
add('logs.throttle',{logs=true},state_parameters(true),state_source,state_validate)
registry['logs.dedupe'].state='local'
registry['logs.throttle'].state='local'

helpers.window_request=function(key,retain,baseline)
    return fb._recipe_window_request(key,retain,baseline)
end
add('window.hold_until',{logs=true},{
    keys={type='selectors',required=true},tenant={type='selector'},
    hold_ms={type='number',required=true},late_ms={type='number',default=60000},
    ready_timeout_ms={type='number',default=60000},max_keys={type='number',default=1024},
    max_key_bytes={type='number',default=1024},
    retain_when={type='map',required=true},keep_when={type='map'},
    overflow={type='string',default='keep',enum={keep=true}},
    on_missing={type='string',default='error',enum={keep=true,error=true}}
},[[return function(p)
    local retain=h.prepare_condition(p.retain_when)
    local baseline=p.keep_when and h.prepare_condition(p.keep_when)
    return function(item)
        local key=h.state_key(item,p)
        if key and h.window_request(key,retain(item),baseline and baseline(item) or false) then
            return 'hold'
        end
    end
end]],function(p,signal,context)
    condition_validate(p.retain_when,signal,context)
    if p.keep_when then condition_validate(p.keep_when,signal,context) end
end)
registry['window.hold_until'].state='window'

local function range(spec,minimum,maximum,integer)
    spec.minimum,spec.maximum,spec.integer=minimum,maximum,integer
end
for _,id in ipairs({'logs.dedupe','logs.throttle'}) do
    for name,maximum in pairs({ttl_ms=86400000,max_keys=65536,max_key_bytes=65536,
        rate=1000000,burst=1000000}) do
        local spec=registry[id].parameters[name]
        if spec then range(spec,1,maximum,true) end
    end
end
for name,maximum in pairs({hold_ms=86400000,late_ms=86400000,ready_timeout_ms=86400000,
    max_keys=65536,max_key_bytes=65536}) do
    range(registry['window.hold_until'].parameters[name],name=='late_ms' and 0 or 1,maximum,true)
end
range(registry['fields.truncate'].parameters.max_bytes,0,1048576,true)
range(registry['metrics.aggregate_dimensions'].parameters.max_exemplars,0,128,true)
registry['metrics.scale'].parameters.factor.exclusive_minimum=0
local metric_window_parameters={interval_ms={type='number',required=true},
    ready_timeout_ms={type='number',default=60000},max_keys={type='number',default=1024},
    max_key_bytes={type='number',default=4096},max_samples={type='number',default=1000000}}
for name,maximum in pairs({interval_ms=86400000,ready_timeout_ms=86400000,max_keys=65536,
    max_key_bytes=65536,max_samples=1000000}) do range(metric_window_parameters[name],1,maximum,true) end
-- Explicit nested models attach to the same parameter registry used for binding.
registry['fields.edit'].parameters.operations.model='field_operations'
registry['logs.validate_fields'].parameters.rules.model='field_rules'
registry['logs.drop_matching'].parameters.condition.model='condition'
registry['window.hold_until'].parameters.retain_when.model='condition'
registry['window.hold_until'].parameters.keep_when.model='condition'
registry['metrics.select'].parameters.keep.model='name_filter'
registry['metrics.select'].parameters.drop.model='name_filter'
registry['metrics.rename'].parameters.mapping.model='metric_mapping'
registry['metrics.aggregate_dimensions'].parameters.keep_attributes.model='attribute_names'
-- Registry data is shared with schema export; executable sources remain private.
function fb._recipe_schema()
    local output={}
    for id,b in pairs(registry) do output[id]={signals=b.signals,parameters=b.parameters,privacy=b.privacy,state=b.state or 'none'} end
    return output
end
function fb._recipe_model()
    return {model_version=1,fts_api_version=1,recipe_version=1,pack_versions={1,2},
        blocks=fb._recipe_schema(),parameter_limits=parameter_limits,
        parameter_kinds=parameter_kinds,recursive_parameter_kinds=recursive_kinds,
        definitions={selector=selector_model,literal=literal_model,condition=condition_model,
            field_operations=operation_parameters,field_rules=field_rule_parameters,
            name_filter=name_filter_parameters,
            metric_mapping={max_entries=128,max_name_bytes=256}},
        constructors={dedupe=registry['logs.dedupe'].parameters,
            throttle=registry['logs.throttle'].parameters,window=registry['window.hold_until'].parameters,
            metric_window=metric_window_parameters},
        recipe_limits=recipe_limits,preflight_required=true}
end
local function environment()
    local public,deterministic_math={},{}
    for k,v in pairs(math) do
        if k~='random' and k~='randomseed' then deterministic_math[k]=v end
    end
    for k,v in pairs(fb) do if k:sub(1,1)~='_' then public[k]=v end end
    return immutable({fb=public,h=helpers,assert=assert,error=error,type=type,tonumber=tonumber,
        tostring=tostring,ipairs=seq,pairs=iter,math=deterministic_math,string=string})
end
function fb._recipe_bind(source, parameters, owned)
    local env=environment()
    local chunk,err
    if setfenv then
        chunk,err=loadstring(source,'fts_block')
        if chunk then setfenv(chunk,env) end
    else chunk,err=load(source,'fts_block','t',env) end
    if not chunk then error('invalid_block',0) end
    local factory=chunk()
    check(type(factory)=='function','type','source')
    local apply=factory(owned and mutable(parameters) or immutable(parameters))
    check(type(apply)=='function','type','source')
    return apply
end
-- JSON configuration remains VM-owned, including on allocation failure.
local function manifest_value(v,depth)
    check(depth<=32,'depth','packs')
    local kind=v:type()
    if kind=='map' then
        local result={}
        for _,key in ipairs(v:keys()) do
            check(result[key]==nil,'duplicate','packs')
            result[key]=manifest_value(v:get(key),depth+1)
        end
        return result
    elseif kind=='array' then
        check(v:len()<=1024,'range','packs')
        local result={}
        for i=1,v:len() do result[i]=manifest_value(v:get(i),depth+1) end
        return result
    elseif kind=='int64' or kind=='uint64' then
        return {type='integer',value=v:value()}
    elseif kind=='double' then return {type='double',value=v:value()}
    elseif kind=='string' or kind=='bool' then return v:value()
    end
    reject('type','packs')
end
local function parameter_defaults(fields,signals)
    for name,spec in pairs(fields) do
        if spec.default~=nil then
            for signal in pairs(signals) do
                schema({[name]=mutable(spec.default)},{[name]=spec},signal,'native')
            end
        end
        if spec.fields then parameter_defaults(spec.fields,signals) end
        if spec.items then parameter_defaults({item=spec.items},signals) end
    end
end
local pack_ids={}
function fb._recipe_register_pack(json,read_source)
    local pack=manifest_value(fb.parse_json(json),0)
    object(pack,{pack_version=true,fts_api_version=true,id=true,version=true,title=true,
        description=true,blocks=true,fixtures=true})
    local pack_version=decimal(pack.pack_version)
    check(pack_version==1 or pack_version==2,'version','pack_version')
    check(decimal(pack.fts_api_version)==1,'version','fts_api_version')
    check(type(pack.id)=='string' and #pack.id<=128 and
        pack.id:match('^[a-z][a-z0-9%.%-]*$'),'type','id')
    check(not pack_ids[pack.id],'duplicate','id')
    check(type(pack.version)=='string' and pack.version:match('^%d+%.%d+%.%d+$'),'version','version')
    list(pack.blocks,64);check(#pack.blocks>0,'missing','blocks')
    for _,block in ipairs(pack.blocks) do
        object(block,{name=true,signals=true,parameters=true,source=true,privacy=true})
        check(type(block.name)=='string' and #block.name<=64 and
            block.name:match('^[a-z][a-z0-9_%-]*$'),'type','name')
        local id=pack.id..'/'..block.name
        check(not registry[id],'duplicate','name')
        list(block.signals,3);check(#block.signals>0,'missing','signals')
        local signals={}
        for _,signal in ipairs(block.signals) do
            check(roots[signal] and not signals[signal],'type','signals');signals[signal]=true
        end
        check(block.privacy==nil or type(block.privacy)=='boolean','type','privacy')
        check(type(block.parameters)=='table','type','parameters')
        parameter_specifications(block.parameters,pack_version,0,{n=0})
        if pack_version==2 then parameter_defaults(block.parameters,signals) end
        check(type(block.source)=='string','type','source')
        add(id,signals,block.parameters,read_source(block.source),nil,block.privacy)
        registry[id].external=true
    end
    pack_ids[pack.id]=pack.version
end

-- Public author API: construct during factory binding, then invoke per item.
-- The native store supplies bounded transactional state; Lua owns policy logic.
local binding_signal,binding_context,binding_input,binding_commit,binding_state
local binding_error_mode,binding_metric_names,binding_scaled,binding_renamed
local function state_factory(options,throttle)
    check(binding_signal=='logs' and binding_input,'input_only','use')
    check(binding_commit=='local','explicit_local','state_commit')
    check(not binding_state,'duplicate','state')
    local p=mutable(options)
    schema(p,registry[throttle and 'logs.throttle' or 'logs.dedupe'].parameters,binding_signal,binding_context)
    state_validate(p)
    fb._recipe_state_configure(throttle and 2 or 1,p.ttl_ms,p.rate or 0,p.burst or 0,p.max_keys,p.max_key_bytes)
    binding_state=true
    p=immutable(p)
    return function(item)
        local key=helpers.state_key(item,p)
        if key and fb._recipe_state_decide(key) then return fb.DROP end
    end
end
function fb.dedupe(options) return state_factory(options,false) end
function fb.throttle(options) return state_factory(options,true) end
function fb.window(options)
    check(binding_signal=='logs' and binding_input,'input_only','use')
    check(binding_commit=='local','explicit_local','state_commit')
    check(not binding_state,'duplicate','state')
    local block=registry['window.hold_until']
    local p=mutable(options)
    schema(p,block.parameters,binding_signal,binding_context)
    block.validate(p,binding_signal,binding_context)
    fb._recipe_window_configure(p.hold_ms,p.late_ms,p.ready_timeout_ms,p.max_keys,p.max_key_bytes)
    binding_state=true
    local retain=prepare_condition(p.retain_when)
    local baseline=p.keep_when and prepare_condition(p.keep_when)
    p=immutable(p)
    return function(item)
        local key=helpers.state_key(item,p)
        if key and fb._recipe_window_request(key,retain(item),baseline and baseline(item) or false) then
            return 'hold'
        end
    end
end

function fb.metric_window(options)
    check(binding_signal=='metrics' and binding_input,'input_only','use')
    check(binding_commit=='local','explicit_local','state_commit')
    check(not binding_state,'duplicate','state')
    local p=mutable(options)
    schema(p,metric_window_parameters,binding_signal,binding_context)
    fb._metric_window_configure(p.interval_ms,p.ready_timeout_ms,p.max_keys,p.max_key_bytes,p.max_samples)
    binding_state=true
    return fb._metric_window_controller()
end

-- Lua numeric literals are doubles; preserve exact integer strings supplied by
-- configuration and explicit typed literals instead of inferring signedness.
local function block_configuration(value)
    if type(value)=='number' then
        check(value==value and math.abs(value)<=9007199254740991,'range','value')
        return {type='double',value=value}
    end
    if type(value)~='table' then return value end
    local result={}
    for key,child in iter(value) do result[key]=block_configuration(child) end
    return result
end
-- Compose validated stateless core blocks without copying their implementation.
function fb.block(id,options)
    check(binding_signal~=nil,'binding_only','use')
    local block=registry[id]
    check(block and not block.external and not block.state,'unsupported','use')
    check(block.signals[binding_signal],'unsupported_signal','use')
    if block.privacy then check(binding_error_mode=='drop','privacy_requires_drop','error_mode') end
    local p=block_configuration(options or {})
    schema(p,block.parameters,binding_signal,binding_context)
    if block.validate then block.validate(p,binding_signal,binding_context) end
    if id=='metrics.rename' then
        binding_metric_names=true
        for source,target in pairs(p.mapping) do
            check(not binding_renamed[target] or binding_renamed[target]==source,'duplicate','mapping')
            binding_renamed[target]=source
            if binding_scaled[source] then binding_scaled[target]=true end
        end
    elseif id=='metrics.scale' then
        for _,name in ipairs(p.names) do binding_scaled[name]=true end
    elseif id=='metrics.merge_histogram_buckets' then
        for _,name in ipairs(p.names) do check(not binding_scaled[name],'order','recipe') end
    end
    return fb._recipe_bind(block.source,p)
end
function fb._recipe_compile(steps,signal,error_mode,context,mark,state_input,state_commit)
    binding_signal,binding_context,binding_input,binding_commit=signal,context,state_input,state_commit
    binding_error_mode,binding_metric_names=error_mode,false
    active_mark,active_step,active_parameter=mark,'initialization','recipe'
    list(steps,recipe_limits.steps);check(#steps>0)
    local bound,ids,scaled,renamed_targets={},{},{},{}
    binding_scaled,binding_renamed=scaled,renamed_targets
    local needs_metric_names=false
    local namespace_selections={}
    local namespace_known=true
    local function namespace_projection(limit)
        if not namespace_known or limit==0 then return nil end
        return function(name)
            for i=1,limit do
                local options=namespace_selections[i]
                if (options.keep and not helpers.name_match(options.keep,name)) or
                    (options.drop and helpers.name_match(options.drop,name)) then return nil end
            end
            return name
        end
    end
    for index,step in ipairs(steps) do
        active_step,active_parameter='initialization','id';mark(active_step)
        object(step,{id=true,use=true,['with']=true,when=true})
        check(type(step.id)=='string' and #step.id<=recipe_limits.id_bytes and step.id:match('^[a-zA-Z][a-zA-Z0-9_%-]*$'))
        active_step=step.id;mark(step.id)
        check(not ids[step.id],'duplicate','id');ids[step.id]=true
        local b=registry[step.use];check(b~=nil,'unknown','use');check(b.signals[signal],'unsupported_signal','use')
        if b.privacy then check(error_mode=='drop','privacy_requires_drop','error_mode') end
        local p=step['with'] or {}
        schema(p,b.parameters,signal,context)
        if b.validate then b.validate(p,signal,context) end
        if step.use=='logs.dedupe' or step.use=='logs.throttle' then
            check(state_input,'input_only','use')
            check(index==#steps,'terminal','use')
            check(state_commit=='local','explicit_local','state_commit')
            fb._recipe_state_configure(step.use=='logs.dedupe' and 1 or 2,p.ttl_ms,
                p.rate or 0,p.burst or 0,p.max_keys,p.max_key_bytes)
        end
        if step.use=='window.hold_until' then
            check(state_input,'input_only','use')
            check(index==#steps,'terminal','use')
            check(state_commit=='local','explicit_local','state_commit')
            fb._recipe_window_configure(p.hold_ms,p.late_ms,p.ready_timeout_ms,p.max_keys,p.max_key_bytes)
        end
        if step.use=='metrics.rename' then
            needs_metric_names=true
            for source,target in pairs(p.mapping) do
                check(not renamed_targets[target] or renamed_targets[target]==source,'duplicate','mapping')
                renamed_targets[target]=source
                if scaled[source] then scaled[target]=true end
            end
        end
        if step.use=='metrics.scale' then for _,n in ipairs(p.names) do scaled[n]=true end end
        if step.use=='metrics.merge_histogram_buckets' then
            for _,n in ipairs(p.names) do
                if scaled[n] then
                    mark(step.id,'invalid_configuration','recipe','order')
                    error('merge_histogram_buckets must precede metrics.scale',0)
                end
            end
        end
        local predicate
        if step.when then condition_validate(step.when,signal,context);predicate=prepare_condition(step.when) end
        bound[index]={id=step.id,apply=fb._recipe_bind(b.source,p,b.external),predicate=predicate,
            projection=namespace_projection(#namespace_selections)}
        -- Selections before a name-changing step are deterministic. Once a
        -- rename or author block can fail/roll back, predicting its result could
        -- hide a surviving name. Subsequent checks keep the original namespace.
        if b.external or step.use=='metrics.rename' then
            namespace_known=false
        elseif namespace_known and not predicate and step.use=='metrics.select' then
            namespace_selections[#namespace_selections+1]=mutable(p)
        end
        if binding_state then check(index==#steps,'terminal','use') end
    end
    binding_signal,binding_context,binding_input,binding_commit=nil,nil,nil,nil
    binding_scaled,binding_renamed=nil,nil
    return function(item)
        if signal=='logs' and context~='any' then
            if fb.is_otel(item)~=(context=='otel') then
                mark('context','invalid_context');error('invalid_context',0)
            end
        end
        for _,step in ipairs(bound) do
            active_metric_projection=step.projection
            mark(step.id)
            -- Only the privileged wrapper catches errors; blocks cannot swallow them.
            local ok,result=pcall(function()
                if not step.predicate or step.predicate(item) then return step.apply(item) end
            end)
            if not ok then
                local class='operation_failed'
                if type(result)=='string' and #result<=256 then
                    local message=result:match('^.-:%d+: (.*)$') or result
                    local allowed={wrong_type=true,unsupported_conversion=true,invalid_parameter=true,
                        invalid_context=true,missing_field=true,collision=true,budget_exceeded=true,invalid_json=true,invalid_timestamp=true,invalid_utf8=true,validation_failed=true}
                    if message=='not enough memory' or message=='Lua policy memory limit exceeded' then class='budget_exceeded'
                    elseif allowed[message] then class=message end
                end
                mark(step.id,class);error(class,0)
            end
            if result~=nil and result~=fb.KEEP and result~=fb.DROP and result~='hold' then
                mark(step.id,'invalid_parameter');error('invalid_parameter',0)
            end
            if result==fb.DROP or result=='hold' then return result end
        end
    end,needs_metric_names or binding_metric_names
end
