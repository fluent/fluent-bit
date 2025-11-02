--[[
   This Lua script is to do the rate limiting of logs based on some key. The Throttle filter in fluent-bit doesn't allow to do the rate limiting based on key
]]

local counter = {}
local time = 0
local group_key = "docker_id" -- Used to group logs. Groups are rate limited independently.
local rate_limit_field = "log" -- The field in the record whose size is used to determine the rate limit
local group_bucket_period_s = 60 -- This is the period of of time in seconds over which group_bucket_limit applies.
local group_bucket_limit = 6000 -- Maximum number logs allowed per groups over the period of group_bucket_period_s.
local group_bucket_limit_bytes = 30000 -- Maximum size of rate_limit_field in bytes allowed per kubernetes.group_key over the period of group_bucket_period_s.

local function get_current_time(timestamp)
    return math.floor(timestamp / group_bucket_period_s)
end

--[[
    This function is used to rate limit logs based on the number of logs of kubernetes.group_key.
    If the number of logs in a group exceeds group_bucket_limit, the log is dropped.
    E.g. With above values for the local variables, each and every containers running on Kubernetes will 
    have a limit of 6000 logs for every 60 seconds since contianers have unique kubernetes.docker_id value

    sample configuration:
    [FILTER]
        Name lua
        Match kube.*
        script rate_limit.lua
        call rate_limit
]]
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

--[[
    This function is used to rate limit logs based on the size of the content of kubernetes.group_key.
    E.g. With above values for the local variables, each and every container running on Kubernetes will
    have a limit of 30000 bytes for every 60 seconds.

    sample configuration:
    [FILTER]
        Name lua
        Match kube.*
        script rate_limit.lua
        call rate_limit_by_size
]]
function rate_limit_by_size(tag, timestamp, record)
    local t = os.time()
    local current_time = get_current_time(t)
    local counter_key = record["kubernetes"][group_key]

    if current_time ~= time then
        time = current_time
        counter = {} -- reset the counter
    end

    if counter[counter_key] == -1 then
        return -1, 0, 0 -- Log group already rate limited. Hence drop it.
    else
        if counter[counter_key] == nil then
            counter[counter_key] = #record[rate_limit_field]
        else
            counter[counter_key] = counter[counter_key] + #record[rate_limit_field]
        end
        if counter[counter_key] > group_bucket_limit_bytes then
            counter[counter_key] = -1 -- value of -1 indicates that this group has been rate limited
            print("Log group " .. group_key .. ": " .. counter_key .. " has been rate limited. Skipping log collection for " .. group_bucket_period_s .. " seconds")
            return -1, 0, 0 -- drop the log
        end
        return 0, 0, 0
    end
end
