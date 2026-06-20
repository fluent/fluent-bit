--[[
   This Lua script is to override timestamp with integer/float epoch time.
   https://github.com/fluent/fluent-bit/issues/662

   sample input is
   [XXXXX.XXXXX, {"KEY_OF_TIMESTAMP"=>1530239065.807368, "data"=>"sample"}]
   
   expected output is
   [1530239065.807368040, {"KEY_OF_TIMESTAMP"=>1530239065.807368, "data"=>"sample"}]


   sample configuration:
   [FILTER]
    Name lua
    Match *.*
    script override_time.lua
    call   override_time
]]

function override_time(tag, timestamp, record)
         -- modify KEY_OF_TIMESTAMP properly.
         return 1, record["KEY_OF_TIMESTAMP"], record
end