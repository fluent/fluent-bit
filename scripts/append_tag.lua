function append_tag(tag, timestamp, record)
    new_record = record
    new_record["tag"] = string.gsub(tag, "([%w_]+)/([%w_]+)/([%w_]+)(.*)", "%1/%2/%3")
    return 1, timestamp, new_record
end
