function append_tag(tag, timestamp, record)
    new_record = record
    -- Takes all [alpha, numeric, :, _, -] characters, and excludes everythign else
    new_record["tag"] = string.gsub(tag, "([%w:_-]+)(.*)", "%1")
    return 1, timestamp, new_record
end
