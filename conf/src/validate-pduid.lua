---Validate IP reputation unique identifier
---@param _pduid string
---@return boolean is_valid
return function(_pduid)
    local cache_pduid = PDUID_cache:get(_pduid)
    if (cache_pduid) then return true end

    local cookie, err = CK_crypto:decrypt(_pduid)
    if err then
        ngx.log(ngx.ERR, err)
        return false
    end

    local expires_at = tonumber(cookie)
    if not expires_at then return false end
    if expires_at < os.time() then return false end

    PDUID_cache:set(_pduid, 1, PDUID_CACHE_EXPIRY)

    return true
end
