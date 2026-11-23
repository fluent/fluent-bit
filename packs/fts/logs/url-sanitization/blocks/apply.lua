local function valid_port(port)
    return #port > 0 and #port <= 5 and port:match('^%d+$') and tonumber(port) <= 65535
end
local function valid_host(host)
    if #host == 0 or #host > 253 or host:sub(1,1) == '.' then return false end
    if host:sub(-1) == '.' then host = host:sub(1, -2) end
    if host:match('^[%d.]+$') then
        local count = 0
        for part in host:gmatch('[^.]+') do
            count = count + 1
            if #part > 3 or tonumber(part) > 255 then return false end
        end
        return count == 4 and not host:find('..', 1, true)
    end
    if host:find('[^A-Za-z0-9.%-]') or host:find('..', 1, true) then return false end
    for label in host:gmatch('[^.]+') do
        if #label > 63 or label:sub(1,1) == '-' or label:sub(-1) == '-' then return false end
    end
    return host:sub(1,1) ~= '.' and #host > 0
end
local function valid_authority(authority)
    if authority:sub(1,1) == '[' then
        local close = authority:find(']', 2, true)
        if not close then return false end
        local address, suffix = authority:sub(2, close-1), authority:sub(close+1)
        if suffix ~= '' and (suffix:sub(1,1) ~= ':' or not valid_port(suffix:sub(2))) then return false end
        if address:find('[^%x:]') or address:find(':::', 1, true) then return false end
        if (address:sub(1,1) == ':' and address:sub(1,2) ~= '::') or
           (address:sub(-1) == ':' and address:sub(-2) ~= '::') then return false end
        local double = address:find('::', 1, true)
        if double and address:find('::', double+2, true) then return false end
        local count = 0
        for part in address:gmatch('[^:]+') do
            count = count+1
            if #part > 4 then return false end
        end
        if double then return count < 8 end
        return count == 8 and address:sub(1,1) ~= ':' and address:sub(-1) ~= ':'
    end
    local colon = authority:find(':', 1, true)
    if colon then
        return valid_host(authority:sub(1, colon-1)) and valid_port(authority:sub(colon+1))
    end
    return valid_host(authority)
end
return function(p)
    return function(log)
        local value = log.body:get(p.field)
        if not value then return end
        if value:type() ~= 'string' then error('wrong_type',0) end
        local text = value:value()
        if #text > 8192 or text:find('[%z\1-\32\127]') or text:find('\\',1,true) then error('invalid_parameter',0) end
        if text:sub(1,1) == '/' and text:sub(1,2) ~= '//' then
            local stop = #text+1
            for _,sep in ipairs({'?','#'}) do local i=text:find(sep,1,true);if i and i<stop then stop=i end end
            log.body:set(p.field,text:sub(1,stop-1));return
        end
        local mark=text:find('://',1,true);if not mark then error('invalid_parameter',0) end
        local scheme=text:sub(1,mark-1):lower();if scheme~='http' and scheme~='https' then error('invalid_parameter',0) end
        local stop=#text+1
        for _,sep in ipairs({'?','#'}) do local i=text:find(sep,mark+3,true);if i and i<stop then stop=i end end
        text=text:sub(1,stop-1)
        local slash=text:find('/',mark+3,true) or (#text+1)
        local authority=text:sub(mark+3,slash-1)
        if authority:find('%',1,true) then error('invalid_parameter',0) end
        local at=authority:find('@',1,true)
        if at then
            if authority:find('@',at+1,true) then error('invalid_parameter',0) end
            authority=authority:sub(at+1)
        end
        if not valid_authority(authority) then error('invalid_parameter',0) end
        log.body:set(p.field,scheme..'://'..authority..text:sub(slash))
    end
end
