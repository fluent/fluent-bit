-- parseable_routing.lua
-- Fluent Bit Lua filter for Parseable Kubernetes autodiscovery
-- 
-- This script processes Kubernetes pod annotations to enable automatic
-- routing of logs to different Parseable streams based on annotations.
--
-- Supported annotations:
--   parseable/dataset      - Target Parseable dataset name
--   parseable/log-source   - Log source type for Parseable
--   parseable/exclude      - Exclude logs from this pod ("true"/"false")
--   parseable/data-type    - Data type (logs/metrics/traces)
--   parseable/env          - Environment tag
--   parseable/service      - Service name tag
--   parseable/version      - Version tag
--   parseable/parser       - Parser to apply to logs

-- Helper function to safely get nested table values
local function safe_get(tbl, ...)
    local value = tbl
    for _, key in ipairs({...}) do
        if type(value) ~= "table" then
            return nil
        end
        value = value[key]
    end
    return value
end

-- Helper function to get annotation with fallback
local function get_annotation(annotations, key, default)
    if annotations == nil then
        return default
    end
    local value = annotations["parseable/" .. key]
    if value == nil or value == "" then
        return default
    end
    return value
end

-- Main processing function called by Fluent Bit
function process_record(tag, timestamp, record)
    -- Get Kubernetes metadata
    local kubernetes = record["kubernetes"]
    if kubernetes == nil then
        -- No Kubernetes metadata, set defaults and pass through
        record["_parseable_dataset"] = "default"
        record["_parseable_log_source"] = "unknown"
        return 1, timestamp, record
    end
    
    -- Get annotations
    local annotations = kubernetes["annotations"]
    local labels = kubernetes["labels"]
    
    -- Check if logs should be excluded
    local exclude = get_annotation(annotations, "exclude", "false")
    if exclude == "true" then
        return -1, timestamp, record  -- Drop the record
    end
    
    -- Extract Parseable routing annotations
    local dataset = get_annotation(annotations, "dataset", nil)
    local log_source = get_annotation(annotations, "log-source", "kubernetes")
    local data_type = get_annotation(annotations, "data-type", "logs")
    
    -- If no dataset annotation, try to derive from labels or namespace
    if dataset == nil then
        -- Try app label first
        if labels and labels["app"] then
            dataset = labels["app"] .. "-logs"
        elseif labels and labels["app.kubernetes.io/name"] then
            dataset = labels["app.kubernetes.io/name"] .. "-logs"
        else
            -- Fall back to namespace-based dataset
            local namespace = kubernetes["namespace_name"] or "default"
            dataset = namespace .. "-logs"
        end
    end
    
    -- Set Parseable routing metadata
    record["_parseable_dataset"] = dataset
    record["_parseable_log_source"] = log_source
    record["_parseable_data_type"] = data_type
    
    -- Extract unified service tagging (similar to Datadog)
    local env = get_annotation(annotations, "env", nil)
    local service = get_annotation(annotations, "service", nil)
    local version = get_annotation(annotations, "version", nil)
    
    -- Fall back to labels for service tagging if annotations not present
    if env == nil and labels then
        env = labels["environment"] or labels["env"]
    end
    if service == nil and labels then
        service = labels["app"] or labels["app.kubernetes.io/name"]
    end
    if version == nil and labels then
        version = labels["version"] or labels["app.kubernetes.io/version"]
    end
    
    -- Add unified service tags to record
    if env then record["environment"] = env end
    if service then record["service"] = service end
    if version then record["version"] = version end
    
    -- Add Kubernetes context for correlation
    record["k8s_namespace"] = kubernetes["namespace_name"]
    record["k8s_pod"] = kubernetes["pod_name"]
    record["k8s_container"] = kubernetes["container_name"]
    record["k8s_node"] = kubernetes["host"]
    
    -- Add pod labels as tags (optional, can be disabled for performance)
    if labels then
        local label_tags = {}
        for k, v in pairs(labels) do
            -- Skip internal Kubernetes labels
            if not string.match(k, "^kubernetes.io/") and
               not string.match(k, "^k8s.io/") and
               not string.match(k, "^helm.sh/") then
                label_tags[k] = v
            end
        end
        if next(label_tags) ~= nil then
            record["k8s_labels"] = label_tags
        end
    end
    
    return 1, timestamp, record
end

-- Container-specific annotation processing
-- Allows different streams for different containers in the same pod
function process_record_with_container_override(tag, timestamp, record)
    -- First do standard processing
    local code, ts, rec = process_record(tag, timestamp, record)
    if code == -1 then
        return code, ts, rec  -- Record was excluded
    end
    
    local kubernetes = rec["kubernetes"]
    if kubernetes == nil then
        return code, ts, rec
    end
    
    local annotations = kubernetes["annotations"]
    if annotations == nil then
        return code, ts, rec
    end
    
    local container_name = kubernetes["container_name"]
    if container_name == nil then
        return code, ts, rec
    end
    
    -- Check for container-specific annotations
    -- Format: parseable/dataset-<container_name>
    local container_dataset = annotations["parseable/dataset-" .. container_name]
    if container_dataset then
        rec["_parseable_dataset"] = container_dataset
    end
    
    -- Check for container-specific exclusion
    local container_exclude = annotations["parseable/exclude-" .. container_name]
    if container_exclude == "true" then
        return -1, ts, rec  -- Drop this container's logs
    end
    
    return 1, ts, rec
end

-- Debug function to print record contents (for troubleshooting)
function debug_record(tag, timestamp, record)
    local json = require("cjson")
    print("=== DEBUG RECORD ===")
    print("Tag: " .. tag)
    print("Record: " .. json.encode(record))
    print("====================")
    return 0, timestamp, record
end
