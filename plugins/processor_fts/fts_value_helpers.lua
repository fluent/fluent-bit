local fb = package.loaded.fluentbit
function fb.keep_keys(map, keys)
  local keep = {}; for _, k in ipairs(keys) do keep[k] = true end
  for _, k in ipairs(map:keys()) do if not keep[k] then map:remove(k) end end
end
function fb.parse_time(text)
  assert(type(text) == 'string', 'timestamp must be RFC3339 text')
  local y,m,d,h,mi,s,tail = text:match('^(%d%d%d%d)%-(%d%d)%-(%d%d)[Tt](%d%d):(%d%d):(%d%d)(.*)$')
  assert(y, 'invalid RFC3339 timestamp')
  y,m,d,h,mi,s = tonumber(y),tonumber(m),tonumber(d),tonumber(h),tonumber(mi),tonumber(s)
  local leap = y%4 == 0 and (y%100 ~= 0 or y%400 == 0)
  local lengths = {31,leap and 29 or 28,31,30,31,30,31,31,30,31,30,31}
  assert(y>=1969 and y<=2107 and m>=1 and m<=12 and d>=1 and d<=lengths[m]
         and h<24 and mi<60 and s<60, 'invalid calendar timestamp')
  local fraction = tail:match('^%.(%d+)')
  local nsec = 0
  if fraction then
    assert(#fraction <= 9, 'timestamp exceeds nanosecond precision')
    nsec = tonumber(fraction .. string.rep('0', 9 - #fraction))
    tail = tail:sub(#fraction + 2)
  end
  local offset = 0
  if tail ~= 'Z' and tail ~= 'z' then
    local sign,oh,om = tail:match('^([+-])(%d%d):(%d%d)$')
    assert(sign and tonumber(oh)<24 and tonumber(om)<60, 'invalid timestamp timezone')
    offset = (tonumber(oh)*60 + tonumber(om))*60*(sign == '+' and 1 or -1)
  end
  local days = 0
  if y == 1969 then days = -365 end
  for year=1970,y-1 do
    days = days + ((year%4 == 0 and (year%100 ~= 0 or year%400 == 0)) and 366 or 365)
  end
  for month=1,m-1 do days = days + lengths[month] end
  local sec = (days+d-1)*86400+h*3600+mi*60+s-offset
  assert(sec>=0 and sec<=4294967293, 'timestamp outside log event range')
  return {sec=sec,nsec=nsec}
end
