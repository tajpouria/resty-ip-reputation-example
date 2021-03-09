local function readAll(file)
    local f = assert(io.open(file, "rb"))
    local content = f:read("*all")
    f:close()
    return content
end

local js = readAll("routing-tbl.json")

local cjson = require('cjson.safe')
local rt, err = cjson.decode(js)
if not rt then ngx.log(ngx.CRIT, err) end

-- Global definitions
RT = rt
Resolver = require "resty.dns.resolver"
DNSBL_Cache = ngx.shared.dnsbl_treat_score_cache
HONEYPOT_ACCESS_KEY = os.getenv("HONEYPOT_ACCESS_KEY")
SEARCH_ENGINE_TRUST_TIME = 86400 -- 1 days
NXDOMAIN_TRUST_TIME = 60 -- 1 min
TRUST_TIME_THRESHOLD = 60 -- 1 min
IP_reputation_handler = require "conf.src.ip-rept-handler"
function string:split(self, sep)
    local fields = {}

    local sep = sep or " "
    local pattern = string.format("([^%s]+)", sep)
    string.gsub(self, pattern, function(c) fields[#fields + 1] = c end)

    return fields
end
