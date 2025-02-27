function process_logs(tag, ts, log)
  return MODIFY, ts, log, {hello = 'world'}
end
