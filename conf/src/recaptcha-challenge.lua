local _M = {}

local function Get(dict, key)
    local json = dict:get(key)
    if not json then return nil end

    return Cjson.decode(json)
end

local function Del(dict, key) dict:delete(key) end

local function Set(dict, key, data, ttl) dict:set(key, Cjson.encode(data), ttl) end

local function googleRecaptchaFinalizing(request_url)
    local res, err = Requests.request("GET", request_url)
    if not res then
        ngx.log(ngx.ERR, err)
        return nil, err
    end

    local json, err = res:json()
    if not json then return nil, err end
    if not json.success then return false, json['error-codes'] end
    return json.success, nil
end

local function render(template, obj)
    local str = ""
    for key, value in pairs(obj) do
        str = "{{" .. key .. "}}"
        template = string.gsub(template, str, value)
    end
    return template
end

function _M.challenge(config)
    if ngx.var.request_method ~= 'GET' then
        ngx.exit(405)
        return
    end

    local RESPONSE_TARGET = config.target or "_challenge_response/recaptcha"
    local PUZZLE_TEMPLATE_LOCATION = config.template or
                                         'conf/src/recaptcha-challenge.html'
    local CLIENT_KEY = config.client_key or ngx.var.remote_addr
    local URL = ngx.var.scheme .. "://" .. ngx.var.host .. ngx.var.request_uri;
    local TRUST_TIME = config.trust_time or 300
    if TRUST_TIME < 300 then TRUST_TIME = 300 end
    local RECAPTCHA_CHALLENGE_SEED_CACHE =
        config.recaptcha_challenge_seed_cache or Recaptcha_challenge_seed_cache

    local obj = {URL = URL, TRUST_TIME = TRUST_TIME}
    Set(RECAPTCHA_CHALLENGE_SEED_CACHE, CLIENT_KEY, obj,
        RECAPTCHA_CHALLENGE_SEED_CACHE_EXPIRY)

    local PUZZLE_TEMPLATE = ""
    local f = io.open(PUZZLE_TEMPLATE_LOCATION, 'r')
    if f ~= nil then
        PUZZLE_TEMPLATE = f:read('*all')
        io.close(f)
    else
        ngx.log(ngx.ERR, 'Could not find template')
        ngx.exit(503)
    end

    local config = ngx.shared.config
    local lang = ngx.var.lang or "en"
    local puzzle_html = render(PUZZLE_TEMPLATE, {
        PUBLIC_KEY = config:get("wcdn_captcha_public_key") or
            RECAPTCHA_PUBLIC_KEY,
        TARGET = RESPONSE_TARGET,
        DIRECTION = config:get(lang .. "_direction") or "ltr",
        PAGE_TITLE = config:get(lang .. "_wcdn_captcha_page_title") or
            "Recaptcha validation title",
        PAGE_MSG = config:get(lang .. "_wcdn_captcha_help_msg") or
            "Recaptcha validation message"
    })

    ngx.header['Content-Type'] = 'text/html; charset=utf-8'
    ngx.say(puzzle_html)
    ngx.exit(ngx.HTTP_OK)
end

function _M.response()
    if ngx.req.get_headers()["x_requested_with"] ~= "XMLHttpRequest" then
        ngx.log(ngx.ERR, "Not XMLHttpReq")
        ngx.exit(405)
        return
    end

    local output = {status = "fail"}

    local args = ngx.req.get_uri_args()
    local response = args.response

    if response then
        local config = ngx.shared.config
        local request_url = (config:get("google_recaptcha_validation_url") or
                                "https://www.google.com/recaptcha/api/siteverify") ..
                                "?secret=" ..
                                (config:get("wcdn_captcha_private_key") or
                                    RECAPTCHA_PRIVATE_KEY) .. "&response=" ..
                                response .. "&remoteip=" .. ngx.var.remote_addr

        local success, err = googleRecaptchaFinalizing(request_url)
        if not success then
            ngx.log(ngx.ERR, err)
            ngx.exit(403)
        end

        output = {status = "success"}
    end

    ngx.header.cache_control = "no-store";
    ngx.say(Cjson.encode(output))
end

return _M
