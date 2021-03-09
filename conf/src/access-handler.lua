local host = ngx.var.host

local conf = RT[host]
if not conf then ngx.exit(409) end
if conf["ip_reputation_enabled"] == 1 then
    local remote_addr = ngx.req.get_headers()['x-remote-addr'] or
                            ngx.var.remote_addr
    if not remote_addr then
        ngx.log(ngx.ERR, "failed to read remote_addr")
        return
    end

    IP_reputation_handler(remote_addr,
                          tonumber(conf["ip_reputation_trust_time"])) -- TODO: Considering remote address from request header for testing purposes

    local js_challenge = require "conf/src/js-challenge"
    js_challenge.challenge {
        log_level = ngx.ERR,
        cookie_lifetime = 10,
        difficulty = 100,
        min_difficulty = 0,
        seed_length = 30,
        seed_lifetime = 60,
        target = "___",
        cookie_name = "_cuid",
        template = 'conf/src/js-challenge.html',
        client_key = remote_addr,
        redis_config = {timeout = 1, host = "127.0.0.1", port = 6379}
    }
end

ngx.var.target_ip = conf["target_ip"]
