#!/usr/bin/env tarantool

local checks = require('checks')
local log = require('log')
local fiber = require('fiber')
local digest = require('digest')
local crypto = require('crypto')
local errors = require('errors')
local json = require('json')

local e_callback = errors.new_class('Auth callback failed')
local DEFAULT_COOKIE_MAX_AGE = 3600*24*30 -- in seconds
local DEFAULT_COOKIE_RENEW_AGE = 3600*24 -- in seconds


local function encode_cookie(cookie, key, max_age)
    checks({ts='number', user='string'}, 'string', 'number')

    local ts = tostring(cookie.ts)

    cookie = {
        ts = ts,
        user = cookie.user,
        hmac = digest.base64_encode(
            crypto.hmac.sha512(key, cookie.user .. ts),
            {nopad = true, nowrap = true, urlsafe = true}
        )
    }

    local raw = json.encode(cookie)
    local lsid = digest.base64_encode(raw,
        {nopad = true, nowrap = true, urlsafe = true}
    )

    return string.format(
        'lsid=%q; Path=/; Max-Age=%d', lsid,
        max_age
    )
end

local function decode_cookie(raw, key)
    checks('string', 'string')

    local msg = digest.base64_decode(raw)
    if msg == nil then
        return nil
    end

    local cookie = json.decode(msg) -- may raise
    if type(cookie) ~= 'table'
    or type(cookie.ts) ~= 'string'
    or type(cookie.user) ~= 'string'
    or type(cookie.hmac) ~= 'string' then
        return nil
    end

    local calc = digest.base64_encode(
        crypto.hmac.sha512(key, cookie.user .. cookie.ts),
        {nopad = true, nowrap = true, urlsafe = true}
    )

    if calc ~= cookie.hmac then
        return nil
    end

    cookie.ts = tonumber(cookie.ts)

    return cookie
end

local function authenticate(self, strategy_names, options)
    checks('table', 'string|table', '?table')

    if strategy_names == nil then

    elseif type(strategy_names) == 'string' then
        strategy_names = {strategy_names}
    end

    return function(req)
        local strategies = self.strategies

        for _, strategy_name in pairs(strategy_names) do
            local strategy = strategies[strategy_name]

            local res, err = strategy:authenticate(req)

            if err ~= nil then
                log.error(err)
                return {
                    status = 500,
                }
            end

            if res.status == 200 and res.user ~= nil then
                local user = self:serialize_user(res.user)

                req.user = user

                local cookie = encode_cookie(
                    {user=user, ts=fiber.time()},
                    self.secret_key,
                    self.cookie_max_age
                )

                if req.next ~= nil then
                    res = req:next()

                    res['headers']['set-cookie'] = cookie

                    return res
                else
                    return {
                        status = 200,
                        headers = {
                            ['set-cookie'] = cookie
                        }
                    }
                end
            end

            if res.status ~= 401 then
                return res
            end
        end

        return {
            status = 401,
        }
    end
end

local function get_user(self, req)
    local cookie_raw = req:cookie('lsid')

    local serialized_user = nil

    if cookie_raw ~= nil then
        local cookie = decode_cookie(cookie_raw, self.secret_key)
        local diff = fiber.time() - cookie.ts
        if diff <= 0 or diff >= self.cookie_max_age then
            return nil
        end

        serialized_user = cookie.user
    end

    local user = self:deserialize_user(serialized_user)

    return user
end

local function auth_required(self)
    checks('table')
    return function(req)
        local cookie_raw = req:cookie('lsid')

        if cookie_raw == nil then
            return {
                status = 401,
            }
        end

        local cookie = decode_cookie(cookie_raw, self.secret_key)

        local diff = fiber.time() - cookie.ts
        if self.cookie_max_age > 0 and (diff <= 0 or diff >= self.cookie_max_age) then
            return {
                status = 401,
                ['set-cookie'] = 'Set-Cookie: lsid=""; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT'
            }
        end

        local user = self:deserialize_user(cookie.user)

        if user == nil then
            return {
                status = 401,
            }
        end

        req.user = user

        local res = req:next()

        if self.cookie_renew_age > 0 and diff > self.cookie_renew_age then
            res['headers']['set-cookie'] = encode_cookie(
                {user=cookie.user, ts=fiber.time()},
                self.secret_key,
                self.cookie_max_age
            )
        end

        return res
    end
end

local function chain(...)
    local callbacks = {...}

    return function(req)
        local i = 0
        local function next_fun(self)
            checks('table')
            i = i + 1

            local callback = callbacks[i]
            if callback == nil then
                return nil
            end
            return callback(self)
        end

        req.next = next_fun

        return req:next()
    end
end

local function new(strategies, options)
    checks(
        'table',
        {serialize_user='?function',
         deserialize_user='?function',
         secret_key='?string',
         cookie_max_age='?number',
         cookie_renew_age='?number',
         success_redirect='?string',
         failure_redirect='?string'
    })

    local strategy_map = {}
    for _, strategy in ipairs(strategies) do
        if type(strategy.authenticate) ~= 'function' then
            error('auth.new(): strategy.authenticate should be a function')
        end

        if type(strategy.name) ~= 'string' then
            error('auth.new(): strategy should have a name')
        end
        strategy_map[strategy.name] = strategy
    end

    local res = {
        strategies = strategy_map,
        serialize_user = options.serialize_user,
        deserialize_user = options.deserialize_user,
        secret_key = options.secret_key or '',
        cookie_max_age = options.cookie_max_age or DEFAULT_COOKIE_MAX_AGE,
        cookie_renew_age = options.cookie_renew_age or DEFAULT_COOKIE_RENEW_AGE,
        success_redirect = options.success_redirect or '/',
        failure_redirect = options.failure_redirect or '/login',
    }

    res.authenticate = authenticate
    res.auth_required = auth_required
    res.get_user = get_user

    return res
end




return {
    new = new,
    encode_cookie = encode_cookie,
    decode_cookie = decode_cookie,
    chain = chain
}
