-- allow C code to pass us options
local opts = LUA_HELPERS_OPTS
LUA_HELPERS_OPTS = nil

local define_enums = function()
  DROP = -1
  KEEP = 0
  MODIFY = 1
  MODIFY_KEEP_TIMESTAMP = 2
  return DROP,
      KEEP,
      MODIFY,
      MODIFY_KEEP_TIMESTAMP
end

local DROP, KEEP, MODIFY, MODIFY_KEEP_TIMESTAMP = define_enums()

local function warn(msg, ...)
  if opts.disable_warnings then
    return
  end
  print(msg:format(...))
end

local function is_array(table)
  return #table > 0 and next(table, #table) == nil
end

local function concat_tables(t1, t2)
  local result = {}
  if type(t1) == 'table' then
    for k, v in pairs(t1) do
      result[k] = v
    end
  end
  if type(t2) == 'table' then
    for k, v in pairs(t2) do
      result[k] = v
    end
  end
  return result
end

local function assign_table(t1, t2, exclude)
  for k, v in pairs(t2) do
    if k ~= exclude then
      t1[k] = v
    end
  end
  return t1
end

-- utility function to process a set of logs/metrics/traces using API similar to Lua classic filter
local function process_records(fn, tag, records, records_metadata, records_timestamps)
  local new_records
  local new_records_metadata
  local new_records_timestamps
  local ingest
  local keep_cnt = 0
  local drop_cnt = 0
  local split_cnt = 0
  local orig_record_count = #records
  local shared_metadata = type(records_metadata) ~= 'table' or not is_array(records_metadata)
  local shared_timestamp = type(records_timestamps) ~= 'table'
  local metadata_changed = false
  local timestamps_changed = false

  for recIndex, record in ipairs(records) do
    local metadata = records_metadata and (records_metadata[recIndex] or records_metadata)
    local ts = records_timestamps and records_timestamps[recIndex] or 0
    local code, new_ts, new_record, new_metadata, new_ingest = fn(tag, ts, record, metadata)

    if code == KEEP then
      -- use original record, only increase keep count
      keep_cnt = keep_cnt + 1
    elseif code == MODIFY or code == MODIFY_KEEP_TIMESTAMP then
      if type(new_record) ~= 'table' then
        error('processor_helper: expected a table as the result of the user function')
      end

      if type(new_metadata) == 'table' then
        metadata_changed = true
        if shared_metadata then
          if (type(records_metadata) == 'table') then
            assign_table(records_metadata, new_metadata)
          end
        else
          records_metadata[recIndex] = new_metadata
        end
      end

      if new_ts and code ~= MODIFY_KEEP_TIMESTAMP then
        if not shared_timestamp then
          timestamps_changed = true
          records_timestamps[recIndex] = new_ts
        end
      end

      if type(new_ingest) == 'table' and is_array(new_ingest) then
        ingest = concat_tables(ingest, new_ingest)
      end

      if is_array(new_record) then
        split_cnt = split_cnt + 1
      end

      records[recIndex] = new_record
    elseif code == DROP then
      records[recIndex] = nil
      drop_cnt = drop_cnt + 1
    else
      warn('processor_helper: unexpected code returned by user function: %s', code)
    end
  end

  new_records = records
  new_records_metadata = records_metadata
  new_records_timestamps = records_timestamps
  if split_cnt > 0 or drop_cnt > 0 then
    -- we need to use a new array since the record count changed
    new_records = {}
    if not shared_metadata then
      new_records_metadata = {}
    end
    if not shared_timestamp then
      new_records_timestamps = {}
    end
    for i = 1, orig_record_count do
      local record = records[i]
      if type(record) == 'table' then

        if is_array(record) then

          for _, rec in ipairs(record) do
            table.insert(new_records, rec)
          end

          if not shared_metadata then
            local rec_md = records_metadata[i]
            if is_array(rec_md) then
              for _, md in ipairs(rec_md) do
                table.insert(new_records_metadata, md)
              end
            else
              for _=1, #record do
                table.insert(new_records_metadata, rec_md)
              end
            end
          end

          if not shared_timestamp then
            local rec_ts = records_timestamps[i]
            if type(rec_ts) == 'table' and is_array(rec_ts) then
              for _, ts in ipairs(rec_ts) do
                table.insert(new_records_timestamps, ts)
              end
            else
              for _=1, #record do
                table.insert(new_records_timestamps, rec_ts)
              end
            end
          end

        else
          table.insert(new_records, record)

          if not shared_metadata then
            table.insert(new_records_metadata, records_metadata[i])
          end

          if not shared_timestamp then
            table.insert(new_records_timestamps, records_timestamps[i])
          end
        end
      end
    end
  end

  return new_records, new_records_metadata, new_records_timestamps, ingest, keep_cnt, drop_cnt
end

local function logs_helper(fn, tag, events)
  local orig_count = #events.logs
  local new_logs, new_metadata, new_timestamps, ingest, keep_cnt, drop_cnt = process_records(fn, tag, events.logs, events.metadata, events.timestamps)
  if keep_cnt == orig_count then
    return 0
  elseif drop_cnt == orig_count then
    return -1
  else
    return 1, ingest, {
      logs = new_logs,
      metadata = new_metadata,
      timestamps = new_timestamps
    }
  end
end

local function metrics_helper(fn, tag, metrics)
  local orig_count = #metrics
  local new_metrics, _, _, ingest, keep_cnt, drop_cnt = process_records(fn, tag, metrics, nil, nil)

  if keep_cnt == orig_count then
    return 0
  elseif drop_cnt == orig_count then
    return -1
  else
    return 1, ingest, new_metrics
  end
end

-- reuse this table to avoid unnecessary allocations between calls to traces_helper
local traces_metadata = {}
local traces_metadata_resourceSpan = {}
local traces_metadata_scopeSpan = {}

local function traces_helper(fn, tag, resourceSpans)
  local ingest
  local resource_keep_cnt = 0
  local resource_drop_cnt = 0
  local orig_resource_spans_count = #resourceSpans

  for resourceSpanIndex, resourceSpan in ipairs(resourceSpans) do
    local orig_scope_spans_count = #resourceSpan.scopeSpans
    local scope_keep_cnt = 0
    local scope_drop_cnt = 0

    for scopeSpanIndex, scopeSpan in ipairs(resourceSpan.scopeSpans) do
      local orig_spans_count = #scopeSpan.spans
      traces_metadata.resourceSpan = traces_metadata_resourceSpan
      traces_metadata.scopeSpan = traces_metadata_scopeSpan
      assign_table(traces_metadata_resourceSpan, resourceSpan, 'scopeSpans')
      assign_table(traces_metadata_scopeSpan, scopeSpan, 'spans')

      local new_spans, new_metadata, _, new_ingest, keep_cnt, drop_cnt = process_records(fn, tag, scopeSpan.spans, traces_metadata, nil)

      if type(new_metadata) == 'table' then
        -- metadata was returned, update the resourceSpan and scopeSpan
        if type(new_metadata.scopeSpan) == 'table' then
          assign_table(scopeSpan, new_metadata.scopeSpan)
          resourceSpan.scopeSpans[scopeSpanIndex] = scopeSpan
        end
        if type(new_metadata.resourceSpan) == 'table' then
          assign_table(resourceSpan, new_metadata.resourceSpan)
          resourceSpans[resourceSpanIndex] = resourceSpan
        end
      end

      if type(new_ingest) == 'table' then
        ingest = concat_tables(ingest, new_ingest)
      end

      if keep_cnt == orig_spans_count then
        scope_keep_cnt = scope_keep_cnt + 1
      elseif drop_cnt == orig_spans_count then
        scope_drop_cnt = scope_drop_cnt + 1
      else
        scopeSpan.spans = new_spans
      end
    end

    if scope_keep_cnt == orig_scope_spans_count then
      resource_keep_cnt = resource_keep_cnt + 1
    elseif scope_drop_cnt == orig_scope_spans_count then
      resource_drop_cnt = resource_drop_cnt + 1
    end
  end

  if resource_keep_cnt == orig_resource_spans_count then
    return 0
  elseif resource_drop_cnt == orig_resource_spans_count then
    return -1
  else
    return 1, ingest, resourceSpans
  end
end

return logs_helper, metrics_helper, traces_helper
