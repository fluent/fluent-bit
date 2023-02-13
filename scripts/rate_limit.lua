--[[
   This Lua script is to do the rate limiting of logs based on some key. The Throttle filter in fluent-bit doesn't allow to do the rate limiting based on key

   sample configuration:
    [FILTER]
     Name lua
     Match kubernetes.*
     script rate_limit.lua
     call rate_limit
]]

local counter = {}
local time = 0
local period = tonumber(os.getenv("PERIOD")) -- Period in seconds. Example: 60
local limit = tonumber(os.getenv("LOGS_LIMIT")) -- Number of logs that can be allowed for the above mentioned period Example: 6000
local key = os.getenv("KEY") -- Key based on which the limit applies. Example: docker_id 

-- with above values, each and every containers running on the kubernetes will have a limit of 6000 logs for every 60 seconds since contianers have unique kubernetes.docker_id value

local function get_current_time(timestamp)
    return math.floor(timestamp / period)
end

function rate_limit(tag, timestamp, record)
    local t = os.time()
    local current_time = get_current_time(t)
    if current_time ~= time then
        time = current_time
        counter = {} -- reset the counter
    end
    local counter_key = record["kubernetes"][key]
    local logs_count = counter[counter_key]
    if logs_count == nil then
        counter[counter_key] = 1
    else
        counter[counter_key] = logs_count + 1
        if counter[counter_key] > limit then -- check if the number of logs is greater than logs limit
            return -1, 0, 0 -- drop the log
        end
    end
    return 0, 0, 0 -- keep the log
end