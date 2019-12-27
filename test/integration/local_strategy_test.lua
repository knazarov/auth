#!/usr/bin/env tarantool

local auth = require('auth')
local local_strategy = require('auth.strategy.local')

local fio = require('fio')
local yaml = require('yaml')
local http_client = require('http.client').new({max_connections = 5})

local t = require('luatest')
local g = t.group('local_strategy')


local root = fio.dirname(fio.abspath(package.search('auth')))
local datadir = fio.pathjoin(root, 'tmp', 'db_test')
local secret_key = 'my-secret-key'

local static_users = {
    {username='user1', password='foo'},
    {username='user2', password='bar'}
}


local function verify(self, username, password)
    for _, user in ipairs(static_users) do
        if user.username == username and user.password == password then
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


local function handler(req)
    return {
        status = 200,
        body = req.user.username
    }
end

local function encode_form(data, boundary)
    local res = ''

    for key, value in pairs(data) do
        res = res .. string.format([[--%s
Content-Disposition: form-data; name="%s"

%s
]], boundary, key, value)
    end
    res = res .. '--' .. boundary
end

t.before_suite(function()
    fio.rmtree(datadir)
    fio.mktree(datadir)
    t.before_suite(function() box.cfg({work_dir = datadir}) end)

    local strategy = local_strategy.new({
            verify = verify,
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

    httpd:route({ path = '/user', method = 'GET' },
        auth.chain(auth_obj:auth_required(), handler))
end)


g.test_local = function()
    local res = http_client:post('127.0.0.1:8080/login')

    t.assert_equals(res.status, 401)

    local res = http_client:post('127.0.0.1:8080/login?username=user1&password=bar')
    t.assert_equals(res.status, 401)


--    local body = encode_form({username='user1', password='foo'}, 'boundary')
--    local res = http_client:post(
--        '127.0.0.1:8080/login',
--        body,
--        {headers={["Content-Type"]='multipart/form-data;boundary="boundary"'}}
--    )
--    t.assert_equals(res.status, 200)

    local res = http_client:post('127.0.0.1:8080/login?username=user1&password=foo')
    t.assert_equals(res.status, 200)

    local lsid = res.cookies.lsid[1]

    local cookie = auth.decode_cookie(lsid, secret_key)
    t.assert_equals(cookie.user, 'user1')

    local res = http_client:get('127.0.0.1:8080/user')
    t.assert_equals(res.status, 401)

    local res = http_client:get('127.0.0.1:8080/user', {headers={cookie = string.format('lsid=%s', lsid)}})
    t.assert_equals(res.status, 200)
    t.assert_equals(res.body, 'user1')


end
