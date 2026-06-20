function append_tag(tag, timestamp, record)
    new_record = record
    new_record["tag"] = tag
    return 1, timestamp, new_record
end
