---@module cert_crypto
local _M = {}

local CK_crypto = {_decipher = nil}

--- Decrypt encrypted cookie
---@param encrypted_cookie string
---@return string|nil cookie
---@return string|nil err
function CK_crypto:decrypt(encrypted_cookie)
    local _, ck =
        pcall(self._decipher.decrypt, self._decipher, encrypted_cookie)
    if not ck then return nil, "decipher.decrypt - decryption failed" end

    return ck, nil
end

--- Encrypt cookie
---@param cookie string
---@return string|nil encrypted_cookie
---@return string|nil err
function CK_crypto:encrypt(cookie)
    local _, enck = pcall(self._decipher.encrypt, self._decipher, cookie)
    if not enck then return nil, "decipher.encrypt - encryption failed" end

    return Str.to_hex(enck), nil
end

--- Cookie crypto constructor
---@param secret_key string
---@return table
function _M:new(secret_key)
    local self = {}
    self._decipher = assert(Aes:new(secret_key)) -- The default cipher is AES 128 CBC with 1 round of MD5
    setmetatable(self, {__index = CK_crypto})

    return self
end

return _M
