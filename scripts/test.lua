--[[

   This Lua script provides 3 interfaces or callbacks for filter_lua:

   - cb_print   => Print records to the standard output
   - cb_drop    => Drop the record
   - cb_replace => Replace record content with a new table

   The key inside each function is to do a proper handling of the
   return values. Each function must return 3 values:

      return code, timestamp, record

   where:

   - code     : -1 record must be deleted
                 0 record not modified, keep the original
                 1 record was modified, replace timestamp and record.
                 2 record was modified, replace record and keep timestamp.
   - timestamp: Unix timestamp with precision (double)
   - record   : Table with multiple key/val

   Uppon return if code == 1 (modified), then filter_lua plugin
   will replace the original timestamp and record with the returned
   values. If code == 0 the original record is kept otherwise if
   code == -1, the original record will be deleted.
]]

-- Print record to the standard output
function cb_print(tag, timestamp, record)
   output = tag .. ":  [" .. string.format("%f", timestamp) .. ", { "

   for key, val in pairs(record) do
      output = output .. string.format(" %s => %s,", key, val)
   end
   
   output = string.sub(output,1,-2) .. " }]"
   print(output)

   -- Record not modified so 'code' return value is 0 (first parameter)
   return 0, 0, 0
end

-- Drop the record
function cb_drop(tag, timestamp, record)
   return -1, 0, 0
end

-- Compose a new JSON map and report it
function cb_replace(tag, timestamp, record)
   -- Record modified, so 'code' return value (first parameter) is 1
   new_record = {}
   new_record["new"] = 12345
   new_record["old"] = record
   return 1, timestamp, new_record
end
