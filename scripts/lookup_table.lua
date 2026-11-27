--[[
    This script runs through a csv file and, using regexes, links a KEY ID from a record to desired columns in a csv table.
    In this example, it increments the record with plus 3 values up to 6 values
    so record with data key M:1 gets NAME 1 - LAT 1 - COUNTRY 1 values, key M:4 gets NAME 4 - LAT 4 - COUNTRY 4 and so on.

    For illustrative purposes, we created a basic CSV table with 6 columns in FILE variable

    We also created a sample record with timestamp and data fields only:
       timestamp: 1530239065.807368
       data:      IP:192.168.0.1 - M:4 - I:Any logged data - S:IGNORED_EVENT

    We will use M:4 as key, but you can change key_regex var to match any value you need.
    
    WARNING: Make sure you have ONLY UNIQUE KEYS in your key columns at your CSV or you will only get the first value it hits.
--]]

--sample record in: [1530239065.807368, {"data":"IP:192.168.0.1 - M:150 - I:Any logged data - S:IGNORED_EVENT"}]
record = {}
record["datetime"] = 1530239065.807368
record["data"] = "IP:192.168.0.1 - M:150 - I:Any logged data - S:IGNORED_EVENT"

--comma separated csv lookup table example file that you can set directly to your csv file path instead of writing it all here.
file = [[1,"John Johnz",40.431,116.570,"Mutian Valley","Beijing",China
2,"Clark Kent",-25.694,-54.435,"Iguaçu","Paraná",Brazil
100,"Bruce Wayne",25.197,55.274,"Downtown","Dubai","United Emirates"
150,"Diana Prince",37.971,23.726,"Partenon","Atena",Greece]]

--regex to get key value from record data so we have a field to search for
key_regex = "[^M]+M:([0-9]+)"

--regex with latin chars to break csv example fields
csv_regex = ",.([%aáÁãÃâÂéÉêÊíÍôÔõÕúÚçÇ ]+).,([0-9-.]+),([0-9-.]+),.([%aáÁãÃâÂéÉêÊíÍôÔõÕúÚçÇ ]+).,.([%aáÁãÃâÂéÉêÊíÍôÔõÕúÚçÇ ]+).,\"?([%aáÁãÃâÂéÉêÊíÍôÔõÕúÚçÇ ]+)"

--function that gets an id, scans csv file and breaks the result groups into table fields
function get_matches(key_id)
         for line in string.gmatch(file, "[^\r\n]+") do
                  --merges key with csv_regex
                  id_regex = key_id .. csv_regex
                  name,lat,lon,city,state,country = string.match(line,id_regex)
                  if name ~= nil then
                          --You should customize these following fields based on values you get from your regex
                          record["heroname"] = name
                          record["secret_lat"] = lat
                          record["country"] = country
                          return record
                  end
         end
end

--function that finds a key from a record using a regex
function extract_id(record)
         key_id = string.match(record["data"], key_regex)
         --condition to skip and leave this record untouched if key_regex returns no value so we save processing
         if key_id ~= nil then
                  get_matches(key_id)
                  --Here we filter out values that are not populated, so we don't create empty fields - you should use some relevant value here
                  if record["heroname"] ~= nil then
                           --print(record["data"],record["heroname"],record["country"])
                           return 2, record["datetime"], record
                  else
                           -- print("Couldn't lookup for a record with key ID " .. key_id)
                           return 0, 0, 0
                  end
         else
                 -- print("Couldn't find ID in this record so we'll keep it original")
                 return 0, 0, 0 
         end
end

extract_id(record)
--sample record out: [1530239065.807368, {"data"=>"IP:192.168.0.1 - M:4 - I:Any logged data - S:IGNORED_EVENT", "heroname"=>"Diana Prince", "secret_lat"=>"37.971", "country"=>"Greece"}]
