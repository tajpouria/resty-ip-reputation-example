local host = ngx.var.host

local conf = RT[host]
if not conf then ngx.exit(409) end
if conf["ip_reputation_enabled"] == 1 then
    local pduid_is_valid = false

    local cookie, err = CK:new()
    if not cookie then
        ngx.log(ngx.ERR, err)
    else
        local _pduid = cookie:get(PDUID_cookie_key)
        if err then
            if err ~= "no cookie found in the current request" then
                ngx.log(ngx.ERR, err)
            end
        elseif _pduid then
            pduid_is_valid = Validate_PDUID(_pduid)
        end
    end

    if not pduid_is_valid then
        -- TODO: Remove remote address from request header for testing purposes
        local remote_addr = ngx.req.get_headers()['x-remote-addr'] or
                                ngx.var.remote_addr
        if not remote_addr then
            ngx.log(ngx.ERR, "failed to read remote_addr")
            return
        end

        local treat_score = DNSBL(remote_addr)
        if treat_score >= tonumber(conf["ip_reputation_treat_score"] or 10) then
            local ip_reputation_challenge = conf["ip_reputation_challenge"]
            if ip_reputation_challenge == "recaptcha" then
                Recaptcha_challenge.challenge {
                    target = "_challenge_response/recaptcha",
                    template = 'conf/src/recaptcha-challenge.html',
                    client_key = remote_addr,
                    trust_time = tonumber(conf["ip_reputation_trust_time"])
                }
            end
            JS_challenge.challenge {
                difficulty = 100,
                min_difficulty = 0,
                seed_length = 30,
                target = "_challenge_response/js",
                template = 'conf/src/js-challenge.html',
                client_key = remote_addr,
                trust_time = tonumber(conf["ip_reputation_trust_time"])
            }
        else

        end
    end
end

ngx.var.target_ip = conf["target_ip"]
