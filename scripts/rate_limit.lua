--[[
   This Lua script is to do the rate limiting of logs based on some key. The Throttle filter in fluent-bit doesn't allow to do the rate limiting based on key

   sample configuration:
    [FILTER]
     Name lua
     Match kube.*
     script rate_limit.lua
     call rate_limit
]]

local counter = {}
local time = 0
local group_key = "container_id" -- Used to group logs. Groups are rate limited independently.
local group_bucket_period_s = 60 -- This is the period of of time in seconds over which group_bucket_limit applies.
local group_bucket_limit = 6000 -- Maximum number logs allowed per groups over the period of group_bucket_period_s.

-- with above values, each and every containers running on the kubernetes will have a limit of 6000 logs for every 60 seconds since contianers have unique kubernetes.container_id value

local function get_current_time(timestamp)
    return math.floor(timestamp / group_bucket_period_s)
end

function rate_limit(tag, timestamp, record)
    local t = os.time()
    local current_time = get_current_time(t)
    if current_time ~= time then
        time = current_time
        counter = {} -- reset the counter
    end
    local counter_key = record["kubernetes"][group_key]
    local logs_count = counter[counter_key]
    if logs_count == nil then
        counter[counter_key] = 1
    else
        counter[counter_key] = logs_count + 1
        if counter[counter_key] > group_bucket_limit then -- check if the number of logs is greater than group_bucket_limit
            return -1, 0, 0 -- drop the log
        end
    end
    return 0, 0, 0 -- keep the log
end