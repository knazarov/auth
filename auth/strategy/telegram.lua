#!/usr/bin/env tarantool

local checks = require('checks')
local errors = require('errors')
local log = require('log')
local yaml = require('yaml')
local fun = require('fun')
local digest = require('digest')
local crypto = require('crypto')

yaml.cfg{encode_invalid_as_nil=true}

local e_callback = errors.new_class('Auth callback failed')


local function render_widget(bot_name, auth_url)
    local widget_template = [[
<html>
<head>
<meta charset="UTF-8">
</head>
<body>
<script async src="https://telegram.org/js/telegram-widget.js?7" data-telegram-login="%s" data-size="large" data-auth-url="%s" data-request-access="write"></script>
</body>
</html>
]]

    return string.format(widget_template, bot_name, auth_url)
end

local function calculate_hmac(tg_data, bot_token)
    checks({id='string',
            first_name='?string',
            last_name='?string',
            username='?string',
            photo_url='?string',
            auth_date='?string',
            hash='?string'},
        'string')

    local without_hash = fun.iter(tg_data):filter(function(x) return x ~= 'hash' end):totable()
    table.sort(without_hash)

    local str_list = {}

    for _, key in ipairs(without_hash) do
        if tg_data[key] == '' then
            table.insert(str_list, string.format('%s=null', key))
        else
            table.insert(str_list, string.format('%s=%s', key, tg_data[key]))
        end
    end

    local str = table.concat(str_list, '\n')

    local hashed_bot_token = digest.sha256(bot_token)

    local hash = crypto.hmac.sha256_hex(hashed_bot_token, str)

    return hash
end

local function authenticate(self, req)
    checks('table', 'table')

    local tg_data = {
        id = req:param('id'),
        first_name = req:param('first_name'),
        last_name = req:param('last_name'),
        username = req:param('username'),
        photo_url = req:param('photo_url'),
        auth_date = req:param('auth_date'),
        hash = req:param('hash')
    }

    if tg_data.id == nil or tg_data.hash == nil then
        local body = render_widget(self._bot_name, self._redirect_url)
        return {
            status = 200,
            body = body
        }
    end

    local hmac = calculate_hmac(tg_data, self._bot_token)

    if tg_data.hash ~= hmac then
        return {
            status = 401
        }
    end

    local res, err = self:_verify(tg_data)

    if err ~= nil then
        log.error(err)
        return {
            status = 500,
        }
    end

    if res == nil then
        return {
            status = 401,
        }
    end

    if type(res) ~= 'table' then
        err = e_callback:new('local_authenticate._verify() must return nil or table')

        log.error(err)
        return {
            status = 500,
        }
    end

    return {
        status = 200,
        user = res
    }
end

local function new(options)
    checks({
            bot_token = 'string',
            bot_name = 'string',
            redirect_url = 'string',
            query_expiration = '?number',
            verify = 'function'})

    return {
        name = 'local',
        authenticate = authenticate,
        _bot_name = options.bot_name,
        _bot_token = options.bot_token,
        _redirect_url = options.redirect_url,
        _query_expiration = options.query_expiration or 86400,
        _verify = options.verify,
    }
end



return {new=new, calculate_hmac=calculate_hmac}
