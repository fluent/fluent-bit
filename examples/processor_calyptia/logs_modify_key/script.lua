-- Load the "opts" object passed in fluent-bit.yaml config into a local
-- variable
local opts = ...

function process_logs(tag, ts, log)
  log.event_type = nil
  log[opts.key] = opts.value
  return MODIFY, ts, log
end
