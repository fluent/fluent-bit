-- Migrate span attributes and drop low-value spans.
local fb = require("fluentbit")

-- Older HTTP semantic convention names and their current replacements. An
-- array keeps the rewrite order, and so the output, deterministic.
local RENAMES = {
    {"http.method", "http.request.method"},
    {"http.status_code", "http.response.status_code"},
}

function process(span)
    local attrs = span.attributes

    -- Health-check traces and cache hits add volume without insight. Both are
    -- leaf spans here; dropping a parent would leave its children orphaned.
    if attrs:get_string("http.route") == "/healthz" then
        return fb.DROP
    end
    if span.name == "cache.lookup" and attrs:get_bool("cache.hit") then
        return fb.DROP
    end

    -- Moving the typed value keeps integers as integers.
    for _, rename in ipairs(RENAMES) do
        local value = attrs:get(rename[1])
        if value then
            attrs:set(rename[2], value)
            attrs:remove(rename[1])
        end
    end

    -- Query strings can carry tokens: keep only the path.
    local target = attrs:get_string("http.target")
    if target then
        attrs:remove("http.target")
        attrs:set("url.path", (target:gsub("%?.*$", "")))
    end

    attrs:remove("enduser.id")
    fb.redact(span.events, {"authorization"})
end
