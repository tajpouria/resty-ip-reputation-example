local function readAll(file)
    local f = assert(io.open(file, "rb"))
    local content = f:read("*all")
    f:close()
    return content
end

local js = readAll("routing-tbl.json")

Cjson = require "cjson.safe"
local rt, err = Cjson.decode(js)
if not rt then ngx.log(ngx.CRIT, err) end

-- Global definitions
RT = rt
DNSBL_cache = ngx.shared.dnsbl_treat_score_cache
JS_challenge_seed_cache = ngx.shared.js_challenge_seed_cache
CK_cache = ngx.shared.ck_cache
HONEYPOT_ACCESS_KEY = os.getenv("HONEYPOT_ACCESS_KEY")
DNSBL_CACHE_SEARCH_ENGINE_EXPIRY = 86400 -- 1 days
DNSBL_CACHE_EXPIRY = 60 -- 1 min
CK_CACHE_EXPIRY = 60 -- 1min
SEED_CACHE_EXPIRY = 60 -- 1min
PDUID_cookie_key = "_pduid"

DNSBL = require "conf.src.dnsbl"
Resolver = require "resty.dns.resolver"
Aes = require "resty.aes"
Sha1 = require "resty.sha1"
CK = require "resty.cookie"
Str = require "resty.string"
JS_challenge = require "conf.src.js-challenge"
CK_crypto = require "conf.src.ck-crypto":new(
                os.getenv("COOKIE_DECRYPTION_BASE64_SECRET"))
function string:split(self, sep)
    local fields = {}

    local sep = sep or " "
    local pattern = string.format("([^%s]+)", sep)
    string.gsub(self, pattern, function(c) fields[#fields + 1] = c end)

    return fields
end
