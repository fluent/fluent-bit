-- Developer-only bridge: load the trusted registry, never an author pack.
assert(os.setlocale('C','numeric'), 'C numeric locale is required')
package.loaded.fluentbit={KEEP='keep',DROP='drop'}
dofile(assert(arg[1], 'registry path is required'))
local seen={}
local function quote(value)
    return '"'..value:gsub('[%z\1-\31\\"]',function(c)
        if c=='"' then return '\\"' end
        if c=='\\' then return '\\\\' end
        return string.format('\\u%04x',string.byte(c))
    end)..'"'
end
local function encode(value,depth)
    assert(depth<64,'model exceeds export depth')
    local kind=type(value)
    if kind=='string' then return quote(value) end
    if kind=='boolean' then return value and 'true' or 'false' end
    if kind=='number' then
        assert(value==value and value~=math.huge and value~=-math.huge,'nonfinite model value')
        return string.format('%.17g',value)
    end
    assert(kind=='table' and not seen[value],'invalid/cyclic model value')
    seen[value]=true
    local array,count=true,0
    for key in pairs(value) do
        count=count+1
        if type(key)~='number' or key<1 or key%1~=0 then array=false end
    end
    array=array and count>0 and count==#value
    local parts={}
    if array then
        for i=1,#value do parts[i]=encode(value[i],depth+1) end
    else
        local keys={}
        for key in pairs(value) do assert(type(key)=='string','invalid model key');keys[#keys+1]=key end
        table.sort(keys)
        for _,key in ipairs(keys) do parts[#parts+1]=quote(key)..':'..encode(value[key],depth+1) end
    end
    seen[value]=nil
    return (array and '[' or '{')..table.concat(parts,',')..(array and ']' or '}')
end
io.write(encode(package.loaded.fluentbit._recipe_model(),0),'\n')
