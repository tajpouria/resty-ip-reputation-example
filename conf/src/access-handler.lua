local host = ngx.var.host

local conf = RT[host]
if not conf then ngx.exit(409) end
if conf["ip_reputation_enabled"] == 1 then
    -- TODO: Remove remote address from request header for testing purposes
    local remote_addr = ngx.req.get_headers()['x-remote-addr'] or
                            ngx.var.remote_addr
    if not remote_addr then
        ngx.log(ngx.ERR, "failed to read remote_addr")
        return
    end

    local treat_score = DNSBL(remote_addr)
    ngx.log(ngx.ERR, treat_score)
    if treat_score >= tonumber(conf["ip_reputation_treat_score"] or 10) then
        JS_challenge.challenge {
            difficulty = 100,
            min_difficulty = 0,
            seed_length = 30,
            target = "___",
            template = 'conf/src/js-challenge.html',
            client_key = remote_addr
        }
    end
end

ngx.var.target_ip = conf["target_ip"]
