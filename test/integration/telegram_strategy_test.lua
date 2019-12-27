#!/usr/bin/env tarantool

local auth = require('auth')
local telegram_strategy = require('auth.strategy.telegram')
local querystring = require('auth.querystring')

local fio = require('fio')
local yaml = require('yaml')
local log = require('log')
local http_client = require('http.client').new({max_connections = 5})

local t = require('luatest')
local g = t.group('telegram_strategy')

local root = fio.dirname(fio.abspath(package.search('auth')))
local datadir = fio.pathjoin(root, 'tmp', 'db_test')
local secret_key = 'my-secret-key'
local bot_token = 'some-bot-token'

local static_users = {
    {id='1', username='user1'},
    {id='2', username='user2'}
}

local function verify(self, tg_data)
    for _, user in ipairs(static_users) do
        if user.id == tg_data.id then
            return user
        end
    end

    return nil
end

local function serialize_user(self, user)
    return user.username
end

local function deserialize_user(self, serialized)
    for _, user in ipairs(static_users) do
        if user.username == serialized then
            return user
        end
    end

    return nil
end


t.before_suite(function()
    fio.rmtree(datadir)
    fio.mktree(datadir)
    t.before_suite(function() box.cfg({work_dir = datadir}) end)

    local strategy = telegram_strategy.new({
            verify = verify,
            bot_name = 'mybot',
            bot_token = bot_token,
            redirect_url = 'http://127.0.0.1:8080/login'
    })

    local auth_obj = auth.new(
        {strategy},
        {
            serialize_user = serialize_user,
            deserialize_user = deserialize_user,
            secret_key = secret_key
        }
    )

    local httpd = require('http.server').new('127.0.0.1', 8080)

    httpd:start()

    httpd:route({ path = '/login', method = 'POST' },
        auth_obj:authenticate('local'))
end)


g.test_telegram = function()
    local res = http_client:post('127.0.0.1:8080/login')
    t.assert_equals(res.status, 200)

    t.assert_str_contains(res.body, 'https://telegram.org/js/telegram-widget.js')


    local tg_data = {
        id = '1',
        first_name = 'Ivan',
        last_name = 'Ivanov',
        username = 'user1',
        photo_url = 'none',
        auth_date = '2030-01-01'
    }
    local hash = telegram_strategy.calculate_hmac(tg_data, bot_token)
    tg_data.hash = hash

    local query = querystring.build(tg_data)

    local res = http_client:post('127.0.0.1:8080/login?'..query)
    t.assert_equals(res.status, 200)

    local lsid = res.cookies.lsid[1]
    local cookie = auth.decode_cookie(lsid, secret_key)
    t.assert_equals(cookie.user, 'user1')
end
