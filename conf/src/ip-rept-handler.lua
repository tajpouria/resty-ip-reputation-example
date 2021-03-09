---Construct a  query name for honeypot-project dnsbl
---Example construct_dnsbl_query_name(127.0.0.1, access_key) -> access_key.1.0.0.127.dnsbl.httpbl.org
---@param remote_addr string
---@param access_key string
---@return string
local function construct_dnsbl_query_name(remote_addr, access_key)
    local split_addr = string:split(remote_addr, ".")
    local r = ""
    for i = #split_addr, 1, -1 do
        if #r == 0 then
            r = split_addr[i]
        else
            r = string.format("%s.%s", r, split_addr[i])
        end
    end

    return string.format("%s.%s.%s", access_key, r, "dnsbl.httpbl.org")
end

---DNSBL lookup for specified query name
---@param name string
---@return table|nil ,string|nil
local function dnsbl_lookup(name)
    local r, err = Resolver:new{
        nameservers = {{"8.8.4.4", 53}},
        timeout = 1000, -- 1 sec
        no_random = true -- always start with first nameserver
    }
    if not r then
        return nil, "failed to instantiate the dnsbl resolver: ", err
    end

    local answers, err, tries = r:query(name, nil, {})
    if not answers then
        return nil,
               string.format(
                   "failed to query the DNS server: %s\n retry historie: %s",
                   err, table.concat(tries, "\n  "))
    end

    if answers.errcode then
        return nil,
               string.format("nameserver returned error code: %s: %s",
                             answers.errcode, answers.errstr)
    end

    if #answers < 1 then return nil, "dnsbl lookup response list has no item" end
    return answers[1], nil
end

---Parse DNSBL response parameter
---https://www.projecthoneypot.org/httpbl_api.php
---@param dnsbl_response_name string
---@return table|nil, string|nil
local function parse_dnsbl_response(dnsbl_response_name)
    local split_res = string:split(dnsbl_response_name, ".")
    if #split_res ~= 4 or split_res[1] ~= "127" then
        return nil,
               string.format("invalid dnsbl response: %s", dnsbl_response_name)
    end
    return {
        stale_days = tonumber(split_res[2]),
        threat_score = tonumber(split_res[3]),
        visitor_type = tonumber(split_res[4])
    }
end

return function(remote_addr)
    local remote_addr = remote_addr or ngx.var.remote_addr
    if not remote_addr then
        ngx.log(ngx.ERR, "failed to read remote_addr")
        return
    end

    local query_name = construct_dnsbl_query_name(remote_addr,
                                                  HONEYPOT_ACCESS_KEY)
    local dnsbl_lookup_res, err = dnsbl_lookup(query_name)
    if not dnsbl_lookup_res then
        ngx.log(ngx.ERR, err)
        return
    end

    local parsed_dnsbl_response, err = parse_dnsbl_response(dnsbl_lookup.name)
    if not parsed_dnsbl_response then
        ngx.log(ngx.ERR, err)
        return
    end
end

