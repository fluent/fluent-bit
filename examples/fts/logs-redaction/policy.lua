-- Redact secrets and enrich OpenTelemetry logs.
local fb = require("fluentbit")

-- Values of these keys are replaced at any depth of the body. Matching is
-- exact and case-insensitive: "Authorization" matches, "db_password" does not.
local SECRET_KEYS = {"password", "authorization", "token", "card"}

local SEVERITIES = {debug = true, info = true, warn = true, error = true, fatal = true}

-- Key redaction never looks inside strings, so free-form text needs its own rules.
local function scrub(text)
    text = text:gsub("[%w%._%+%-]+@[%w%.%-]+", "<email>")
    text = text:gsub("token=%S+", "token=[REDACTED]")
    return text
end

function process(log)
    if not fb.is_otel(log) then
        return
    end

    -- Health checks carry no information worth shipping.
    if log.attributes:get_string("http.route") == "/healthz" then
        return fb.DROP
    end

    fb.redact(log.body, SECRET_KEYS)

    local text = log.body:get_string("msg")
    if text then
        log.body:set("msg", scrub(text))
    end

    -- Keep only the domain of the user address.
    local email = log.attributes:get_string("user.email")
    if email then
        log.attributes:remove("user.email")
        log.attributes:set("user.email_domain", email:match("@(.+)$") or "unknown")
    end

    local level = log.body:get_string("level")
    if level and SEVERITIES[level] then
        fb.set_severity(log, level)
    end

    log.resource.attributes:set("deployment.environment.name", "production")
    log.attributes:set("policy.name", "logs-redaction")
end
