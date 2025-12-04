function enrich_logs(tag, timestamp, record)
    -- Add processing timestamp
    record["processed_at"] = os.date("!%Y-%m-%dT%H:%M:%SZ")
    
    -- Add severity level based on log level
    if record["level"] then
        local level = string.lower(record["level"])
        if level == "error" or level == "fatal" or level == "critical" then
            record["severity"] = "high"
            record["alert"] = true
        elseif level == "warn" or level == "warning" then
            record["severity"] = "medium"
            record["alert"] = false
        else
            record["severity"] = "low"
            record["alert"] = false
        end
    end
    
    -- Add log source identifier
    if string.match(tag, "application") then
        record["log_type"] = "application"
        record["category"] = "business_logic"
    elseif string.match(tag, "error") then
        record["log_type"] = "error"
        record["category"] = "system_error"
    elseif string.match(tag, "system") then
        record["log_type"] = "system"
        record["category"] = "infrastructure"
    end
    
    -- Add custom metadata
    record["pipeline"] = "fluent-bit-parseable"
    record["processed_by"] = "fluent-bit-v4.2.1"
    
    return 2, timestamp, record
end
