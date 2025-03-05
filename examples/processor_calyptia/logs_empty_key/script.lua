function process_logs(tag, ts, log)
  for k, v in pairs(log) do
    if v == "" then
      log[k] = 'EMPTY'
    end
  end
  return MODIFY, ts, log
end
