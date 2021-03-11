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
---@return table dnsbl_response
---@return string|nil err
local function dnsbl_lookup(name)
    local nxdomain_addr = {address = "127.0.0.1"}

    local r, err = Resolver:new{
        nameservers = {{"8.8.4.4", 53}},
        timeout = 1000, -- 1 sec
        no_random = true -- always start with first nameserver
    }
    if not r then
        return nxdomain_addr, "failed to instantiate the dnsbl resolver: ", err
    end

    local answers, err, tries = r:query(name, nil, {})
    if not answers then
        return nxdomain_addr,
               string.format(
                   "failed to query the DNS server: %s\n retry histories: %s",
                   err, table.concat(tries, "\n  "))
    end

    -- NXDOMAIN
    if answers.errcode == 3 then return {address = "127.0.0.1"}, nil end
    if answers.errcode then
        return nxdomain_addr,
               string.format("nameserver returned error code: %s: %s",
                             answers.errcode, answers.errstr)
    end

    if #answers < 1 then
        return nxdomain_addr, "dnsbl lookup response list has no item"
    end
    return answers[1], nil
end

---Parse DNSBL response parameters
---https://www.projecthoneypot.org/httpbl_api.php
---@param dnsbl_response_addr string
---@return table parsed_dnsbl_response
---@return string|nil err
local function parse_dnsbl_response(dnsbl_response_addr)
    local split_res = string:split(dnsbl_response_addr, ".")
    if #split_res ~= 4 or split_res[1] ~= "127" then
        return {stale_days = 0, threat_score = 0, visitor_type = 1},
               string.format("invalid dnsbl response: %s", dnsbl_response_addr)
    end

    return {
        stale_days = tonumber(split_res[2]),
        threat_score = tonumber(split_res[3]),
        visitor_type = tonumber(split_res[4])
    }
end

--- DNSBL
---@param remote_addr string
---@return number treat_score
return function(remote_addr)
    local cache_treat_score = tonumber(DNSBL_cache:get(remote_addr))
    if cache_treat_score then return cache_treat_score end

    local query_name = construct_dnsbl_query_name(remote_addr,
                                                  HONEYPOT_ACCESS_KEY)
    local dnsbl_lookup_res, err = dnsbl_lookup(query_name)
    if err then ngx.log(ngx.ERR, err) end

    local parsed_dnsbl_response, err = parse_dnsbl_response(
                                           dnsbl_lookup_res.address)
    if err then ngx.log(ngx.ERR, err) end

    -- Search engine
    if parsed_dnsbl_response.visitor_type == 0 then
        DNSBL_cache:set(remote_addr, -1, DNSBL_CACHE_SEARCH_ENGINE_EXPIRY)
        return -1
    end

    local treat_score = parsed_dnsbl_response.threat_score
    DNSBL_cache:set(remote_addr, treat_score, DNSBL_CACHE_EXPIRY)

    return treat_score
end
