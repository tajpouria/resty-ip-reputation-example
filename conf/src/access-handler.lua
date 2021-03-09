local host = ngx.var.host

local conf = RT[host]
if not conf then ngx.exit(409) end
if conf["ip_reputation_enabled"] == 1 then
    IP_reputation_handler(ngx.req.get_headers()['x-remote-addr']) -- TODO: Considering remote address from request header for testing purposes
end

ngx.var.target_ip = conf["target_ip"]
