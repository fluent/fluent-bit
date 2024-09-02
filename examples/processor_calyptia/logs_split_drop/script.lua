local i = 0

function process_logs(tag, ts, log)
  ts = i
  log.event_type = log.event_type .. " " .. i
  i = i + 1
  if i % 2 == 0 then
    return DROP
  end
  return MODIFY, {ts, ts + 10}, {log, log}, {index = i + 5}
end
