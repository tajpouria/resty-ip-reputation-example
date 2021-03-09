local host = ngx.var.host

local conf = RT[host]
if not conf then ngx.exit(409) end
if conf["ip_reputation_enabled"] == 1 then
    local remote_addr = ngx.req.get_headers()['x-remote-addr']
    if not remote_addr then
        ngx.log(ngx.ERR, "failed to read remote_addr")
        return
    end

    IP_reputation_handler(remote_addr, tonumber(conf["ip_reputation_trust_time"])) -- TODO: Considering remote address from request header for testing purposes
end

ngx.var.target_ip = conf["target_ip"]
