local _M = {}

local function sha1(data)
    local s = Resty_sha1:new()
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
    local json = dict:get(key)
    if not json then return nil end

    return Cjson.decode(json)
end

local function Del(dict, key) dict:delete(key) end

local function Set(dict, key, data, ttl) dict:set(key, Cjson.encode(data), ttl) end

function _M.challenge(config)
    local LOG_LEVEL = config.log_level or ngx.NOTICE

    local BASIC_DIFFICULTY = config.difficulty or 100
    local MIN_DIFFICULTY = config.min_difficulty or 0
    local SEED_LIFETIME = config.lifetime or 60
    local RESPONSE_TARGET = config.target or "___"
    local COOKIE_NAME = config.cookie or "_cuid"
    local PUZZLE_TEMPLATE_LOCATION = config.template or
                                         '/etc/nginx/html/puzzle.html'
    local CLIENT_KEY = config.client_key or ngx.var.remote_addr

    local JS_CHALLENGE_SEED_CACHE = config.js_challenge_seed_cache or
                                        JS_challenge_seed_cache

    local COOKIE_FETCH_KEY = "COOKIE_" .. CLIENT_KEY

    local SEED_FETCH_KEY = "SEED_" .. CLIENT_KEY

    local authenticated = false

    local field = false
    -- Create URL
    local URL = ngx.var.scheme .. "://" .. ngx.var.host .. ngx.var.request_uri;

    local cookie, err = CK:new()
    if not cookie then
        ngx.log(LOG_LEVEL, err)
        ngx.exit(503)
        return
    end

    field, err = cookie:get(COOKIE_NAME)
    if field then
        local data = Get(JS_CHALLENGE_SEED_CACHE, COOKIE_FETCH_KEY)
        if data ~= nil then
            if data == field then
                authenticated = true
                ngx.header.cache_control = "no-store";
                return true
            end
        end
    end

    if ngx.var.request_method ~= 'GET' then
        if not authenticated then
            -- ngx.exit(ngx.HTTP_FORBIDDEN)
            ngx.exit(405)
        end
    end

    -- Set client key for SEED

    local TRYS = 1

    local SEED = ""
    local POW = ""
    local reuse = false

    local DIFF = BASIC_DIFFICULTY * TRYS

    local redis_fetch = Get(JS_CHALLENGE_SEED_CACHE, SEED_FETCH_KEY)

    -- If not set in REDIS, then do some work

    local obj = {}

    local now = os.time();

    if redis_fetch == nil then
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
            URL = URL
        }
        -- Set to REDIS, so it can be fetched
        Set(JS_CHALLENGE_SEED_CACHE, SEED_FETCH_KEY, obj, SEED_LIFETIME)
    else
        -- Bump trys
        TRYS = tonumber(redis_fetch['TRYS']) + 1

        -- Make it harder
        DIFF = BASIC_DIFFICULTY * TRYS
        obj = {
            POW = redis_fetch['POW'],
            SEED = redis_fetch['SEED'],
            HASH = redis_fetch['HASH'],
            TRYS = TRYS,
            DIFF = DIFF,
            TIME = now,
            TARGET = redis_fetch['TARGET'],
            URL = redis_fetch['URL']
        }

        -- Set to REDIS, so trycount we can bump trycount and Time
        Set(JS_CHALLENGE_SEED_CACHE, SEED_FETCH_KEY, obj, SEED_LIFETIME)
        -- obj = redis_fetch
    end

    -- For debugging , output JSON
    -- ngx.say(cjson.encode(obj))

    -- Set template as string
    local PUZZLE_TEMPLATE = ""

    -- Open file
    local f = io.open(PUZZLE_TEMPLATE_LOCATION, 'r')

    -- If file not open, then throw error
    if f ~= nil then

        -- Read all file
        PUZZLE_TEMPLATE = f:read('*all')
        io.close(f)
    else
        -- Log if error and exit with error code
        ngx.log(LOG_LEVEL, 'Could not find template')
        ngx.exit(503)
    end

    local puzzle_html = render(PUZZLE_TEMPLATE, obj)

    -- Render the template to users
    -- ngx.header["Cache-Control"] = "no-cache, no-store, must-revalidate"
    -- ngx.header["Cache-Control"] = "max-age: 0"
    -- ngx.header["Pragma"] = "no-cache"
    -- ngx.header["Expires"] = "0"

    ngx.header['Content-Type'] = 'text/html; charset=UTF-8'
    ngx.say(puzzle_html)
    ngx.exit(ngx.HTTP_OK)

    -- ngx.exit(405) 
end

function _M.response(config)
    local LOG_LEVEL = config.log_level or ngx.NOTICE

    local COKKIE_LIFETIME = config.session_lifetime or 604800
    local COOKIE_NAME = config.cookie or "_cuid"
    local CLIENT_KEY = config.client_key or ngx.var.remote_addr
    local TIMEZONE = config.timezone or "GMT"
    local HTTP_ONLY = config.http_only_cookie or false
    local SECURE = config.cookie_secure or false
    local COOKIE_DOMAIN = config.cookie_domain or ngx.var.host
    local COOKIE_PATH = config.cookie_domain or "/"

    local MIN_TIME = config.min_time or 2

    -- Redis Config
    local JS_CHALLENGE_SEED_CACHE = config.js_challenge_seed_cache or
                                        JS_challenge_seed_cache

    -- Ger all args as Lua object
    local args = ngx.req.get_uri_args()

    local SEED = args.SEED
    local POW = tonumber(args.POW)
    local RD_POW = 0
    local TIMEDIFF = 0
    local req_headers = ngx.req.get_headers()
    local COOKIE_EXPIRES = ""
    local COOKIE_VALUE = RandomString(20)

    TIMEZONE = " " .. TIMEZONE

    local now = os.time();

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

    -- expecting an Ajax GET
    if req_headers.x_requested_with ~= "XMLHttpRequest" then
        ngx.log(ngx.ERR, "Not XMLHttpReq")
        ngx.exit(405)
        return
    end

    ----- Authentication checks done --

    local cookie, err = CK:new()
    if not cookie then
        ngx.log(LOG_LEVEL, err)
        return
    end

    local output = {}

    output.status = "fail"

    local data = Get(JS_CHALLENGE_SEED_CACHE, SEED_FETCH_KEY)

    if data then
        -- Found, check if valid
        RD_POW = data["POW"]

        TIMEDIFF = now - data['TIME']

        if (POW == RD_POW) then
            if TIMEDIFF >= MIN_TIME then
                COOKIE_EXPIRES = os.date('%a, %d %b %Y %X',
                                         os.time() + COKKIE_LIFETIME) ..
                                     TIMEZONE
                local ok, err = cookie:set(
                                    {
                        key = COOKIE_NAME,
                        value = COOKIE_VALUE,
                        path = COOKIE_PATH,
                        domain = COOKIE_DOMAIN,
                        secure = SECURE,
                        httponly = HTTP_ONLY,
                        expires = COOKIE_EXPIRES,
                        max_age = COKKIE_LIFETIME
                    })

                -- Log to redis with long lifetime
                Set(JS_CHALLENGE_SEED_CACHE, COOKIE_FETCH_KEY, COOKIE_VALUE,
                    COKKIE_LIFETIME)

                output.status = "success"
                output.redirect = data['URL']
                Del(JS_CHALLENGE_SEED_CACHE, SEED_FETCH_KEY)
            else
                output.message = "To fast !"
                output.time = TIMEDIFF
            end
        end
    end

    ngx.header.cache_control = "no-store";
    -- ngx.header["Cache-Control"] = "no-cache, no-store, must-revalidate"
    -- ngx.header["Cache-Control"] = "max-age: 0"
    -- ngx.header["Pragma"] = "no-cache"
    -- ngx.header["Expires"] = "0"

    -- output.data=redis_fetch
    ngx.say(Cjson.encode(output))
end

return _M
