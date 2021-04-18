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
DNSBL_cache = ngx.shared.dnsbl_cache
JS_challenge_seed_cache = ngx.shared.js_challenge_seed_cache
Recaptcha_challenge_seed_cache = ngx.shared.recaptcha_challenge_seed_cache
PDUID_cache = ngx.shared.pduid_cache
HONEYPOT_ACCESS_KEY = os.getenv("HONEYPOT_ACCESS_KEY")
RECAPTCHA_PUBLIC_KEY = os.getenv("RECAPTCHA_PUBLIC_KEY")
RECAPTCHA_PRIVATE_KEY = os.getenv("RECAPTCHA_PRIVATE_KEY")
DNSBL_CACHE_SEARCH_ENGINE_EXPIRY = 86400 -- 1 days
DNSBL_CACHE_EXPIRY = 5
PDUID_CACHE_EXPIRY = 5
JS_CHALLENGE_SEED_CACHE_EXPIRY = 5
RECAPTCHA_CHALLENGE_SEED_CACHE_EXPIRY = 900
PDUID_cookie_key = "_pduid"

DNSBL = require "conf.src.dnsbl"
Resolver = require "resty.dns.resolver"
Aes = require "resty.aes"
Sha1 = require "resty.sha1"
CK = require "resty.cookie"
Requests = require "resty.requests"
Str = require "resty.string"
Validate_PDUID = require "conf.src.validate-pduid"
JS_challenge = require "conf.src.js-challenge"
Recaptcha_challenge = require "conf.src.recaptcha-challenge"

CK_crypto = require "conf.src.ck-crypto":new(
                os.getenv("COOKIE_DECRYPTION_BASE64_SECRET"))
function string:split(self, sep)
    local fields = {}

    local sep = sep or " "
    local pattern = string.format("([^%s]+)", sep)
    string.gsub(self, pattern, function(c) fields[#fields + 1] = c end)

    return fields
end
