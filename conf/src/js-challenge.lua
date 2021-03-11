local _M = {}

local function sha1(data)
    local s = Sha1:new()
    if not s then
        ngx.log(ngx.ERR, "failed to create the sha1 object")
        return
    end

    local ok = s:update(data)
    if not ok then
        ngx.log(ngx.ERR, "failed to add sha1 data")
        return
    end

    local digest = s:final()
    return Str.to_hex(digest)
end

local function CreatePow(min, max)
    math.randomseed(os.time());
    return math.random(min, max);
end

local function render(template, obj)
    local str = ""
    -- TODO: Need faster template engine
    for key, value in pairs(obj) do
        str = "::" .. key .. "::"
        template = string.gsub(template, str, value)
    end
    return template
end

local function RandomString(length)
    length = length or 1
    if length < 1 then return nil end

    math.randomseed(os.time());
    local chars = "qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM";
    local charlength = string.len(chars);
    local array = {}
    for i = 1, length do
        local rand = math.random(0, charlength)
        array[i] = string.sub(chars, rand, rand + 1);
    end
    return table.concat(array)
end

local function Get(dict, key)
    -- TODO: Handle err
    local json = dict:get(key)
    if not json then return nil end

    -- TODO: Handle err
    return Cjson.decode(json)
end

local function Del(dict, key)
    -- TODO: Handle err
    dict:delete(key)
end

local function Set(dict, key, data, ttl)
    -- TODO: Handle err
    dict:set(key, Cjson.encode(data), ttl)
end

function _M.challenge(config)
    local BASIC_DIFFICULTY = config.difficulty or 100
    local MIN_DIFFICULTY = config.min_difficulty or 0
    local TRUST_TIME = config.TRUST_TIME or 300 -- TODO: Check for minimum 5 min
    local RESPONSE_TARGET = config.target or "___"
    local PUZZLE_TEMPLATE_LOCATION = config.template or
                                         '/etc/nginx/html/puzzle.html'
    local CLIENT_KEY = config.client_key or ngx.var.remote_addr

    local CK_CACHE = config.ck_cache or CK_cache
    local JS_CHALLENGE_SEED_CACHE = config.js_challenge_seed_cache or
                                        JS_challenge_seed_cache

    local COOKIE_FETCH_KEY = "COOKIE_" .. CLIENT_KEY

    local SEED_FETCH_KEY = "SEED_" .. CLIENT_KEY

    local field = false
    -- Create URL
    local URL = ngx.var.scheme .. "://" .. ngx.var.host .. ngx.var.request_uri;

    local cookie, err = CK:new()
    if not cookie then
        ngx.log(ngx.ERR, err)
        ngx.exit(503)
        return
    end

    field, err = cookie:get(PDUID_cookie_key)
    if field then
        local data = Get(CK_CACHE, COOKIE_FETCH_KEY)
        if data == field then
            ngx.header.cache_control = "no-store";
            return true
        end
    end

    if ngx.var.request_method ~= 'GET' then
        ngx.exit(405)
        return
    end

    -- Set client key for SEED

    local TRYS = 1

    local SEED = ""
    local POW = ""

    local DIFF = BASIC_DIFFICULTY * TRYS

    local data = Get(JS_CHALLENGE_SEED_CACHE, SEED_FETCH_KEY)

    local now = os.time();

    local obj = {}

    if data == nil then
        SEED = RandomString(30)
        -- Create Proof Of Work integer
        POW = CreatePow(MIN_DIFFICULTY, DIFF);

        -- Create string for SHA1
        local sha1_string = SEED .. POW

        -- SHA1 string
        local HASH = sha1(sha1_string)

        -- Get time NOW in epoch

        obj = {
            POW = POW,
            SEED = SEED,
            HASH = HASH,
            TRYS = TRYS,
            DIFF = DIFF,
            TIME = now,
            TARGET = RESPONSE_TARGET,
            URL = URL,
            TRUST_TIME = TRUST_TIME
        }
        -- Set to REDIS, so it can be fetched
        Set(JS_CHALLENGE_SEED_CACHE, SEED_FETCH_KEY, obj, SEED_CACHE_EXPIRY)
    else
        -- Bump trys
        TRYS = tonumber(data['TRYS']) + 1

        -- Make it harder
        DIFF = BASIC_DIFFICULTY * TRYS
        obj = {
            POW = data['POW'],
            SEED = data['SEED'],
            HASH = data['HASH'],
            TRYS = TRYS,
            DIFF = DIFF,
            TIME = now,
            TARGET = data['TARGET'],
            URL = data['URL'],
            TRUST_TIME = TRUST_TIME
        }

        -- Set to REDIS, so trycount we can bump trycount and Time
        Set(JS_CHALLENGE_SEED_CACHE, SEED_FETCH_KEY, obj, SEED_CACHE_EXPIRY)
    end

    -- Set template as string
    local PUZZLE_TEMPLATE = ""

    -- Open file
    -- TODO: Read template once
    local f = io.open(PUZZLE_TEMPLATE_LOCATION, 'r')

    -- If file not open, then throw error
    if f ~= nil then

        -- Read all file
        PUZZLE_TEMPLATE = f:read('*all')
        io.close(f)
    else
        -- Log if error and exit with error code
        ngx.log(ngx.ERR, 'Could not find template')
        ngx.exit(503)
    end

    local puzzle_html = render(PUZZLE_TEMPLATE, obj)

    ngx.header['Content-Type'] = 'text/html; charset=UTF-8'
    ngx.say(puzzle_html)
    ngx.exit(ngx.HTTP_OK)
end

function _M.response(config)
    -- TODO: Is that really necessary?
    -- expecting an Ajax GET
    if ngx.req.get_headers()["x_requested_with"] ~= "XMLHttpRequest" then
        ngx.log(ngx.ERR, "Not XMLHttpReq")
        ngx.exit(405)
        return
    end

    local CLIENT_KEY = config.client_key or ngx.var.remote_addr
    local TIMEZONE = config.timezone or "GMT"
    local HTTP_ONLY = config.http_only_cookie or false
    local SECURE = config.cookie_secure or false
    local COOKIE_DOMAIN = config.cookie_domain or ngx.var.host
    local COOKIE_PATH = config.cookie_domain or "/"

    local MIN_TIME = config.min_time or 2

    local CK_CACHE = config.ck_cache or CK_cache
    local JS_CHALLENGE_SEED_CACHE = config.js_challenge_seed_cache or
                                        JS_challenge_seed_cache

    -- Ger all args as Lua object
    local args = ngx.req.get_uri_args()

    local SEED = args.SEED
    local POW = tonumber(args.POW)
    local RD_POW = 0
    local TIMEDIFF = 0
    local COOKIE_EXPIRES = ""

    TIMEZONE = " " .. TIMEZONE

    if not SEED then
        ngx.exit(ngx.HTTP_FORBIDDEN)
        return
    end

    if not POW then
        ngx.exit(ngx.HTTP_FORBIDDEN)
        return
    end

    local COOKIE_FETCH_KEY = "COOKIE_" .. CLIENT_KEY;

    local SEED_FETCH_KEY = "SEED_" .. CLIENT_KEY;

    ----- Authentication checks done --

    local cookie, err = CK:new()
    if not cookie then
        ngx.log(ngx.ERR, err)
        return
    end

    local output = {}

    output.status = "fail"

    local data = Get(JS_CHALLENGE_SEED_CACHE, SEED_FETCH_KEY)

    if data then
        -- Found, check if valid
        RD_POW = data["POW"]

        local now = os.time()

        TIMEDIFF = now - data['TIME']

        local COOKIE_LIFETIME = data['TRUST_TIME']

        if (POW == RD_POW) then
            if TIMEDIFF >= MIN_TIME then
                -- TODO: Handle err
                local cookie_value, err =
                    CK_crypto:encrypt(now + COOKIE_LIFETIME)
                if not cookie_value then
                    ngx.log(ngx.ERR, err)
                    return
                end

                COOKIE_EXPIRES = os.date('%a, %d %b %Y %X',
                                         now + COOKIE_LIFETIME) .. TIMEZONE
                -- TODO: Handler err
                local ok, err = cookie:set(
                                    {
                        key = PDUID_cookie_key,
                        value = cookie_value,
                        path = COOKIE_PATH,
                        domain = COOKIE_DOMAIN,
                        secure = SECURE,
                        httponly = HTTP_ONLY,
                        expires = COOKIE_EXPIRES,
                        max_age = COOKIE_LIFETIME
                    })

                Set(CK_CACHE, COOKIE_FETCH_KEY, cookie_value, CK_CACHE_EXPIRY)

                output.status = "success"
                output.redirect = data['URL']
                Del(JS_CHALLENGE_SEED_CACHE, SEED_FETCH_KEY)
            else
                output.message = "Too fast!"
                output.time = TIMEDIFF
            end
        end
    end

    ngx.header.cache_control = "no-store";
    ngx.say(Cjson.encode(output))
end

return _M
