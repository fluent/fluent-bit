-- Normalize metric units and reduce series cardinality.
local fb = require("fluentbit")

-- Attributes that identify a request series. Anything else, such as a
-- per-client identifier, is removed and its series are summed together.
local SERIES_KEYS = {"http.route", "http.response.status_code"}

function process(metric)
    -- Internal debugging families never leave the host.
    if metric.name:sub(1, 6) == "debug." then
        return fb.DROP
    end

    -- Convert to the base units recommended by OpenTelemetry. scale_metric
    -- updates values, sums, histogram bounds and exemplars together.
    if metric.unit == "ms" then
        fb.scale_metric(metric, 0.001, "s")
    elseif metric.unit == "KiBy" then
        fb.scale_metric(metric, 1024, "By")
    end

    if metric.name == "http.server.duration" then
        metric.name = "http.server.request.duration"
    end

    if metric.name == "http.server.requests" then
        fb.aggregate_metric(metric, SERIES_KEYS, "sum")
    end
end
