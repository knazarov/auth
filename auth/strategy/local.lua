#!/usr/bin/env tarantool

local checks = require('checks')
local errors = require('errors')
local log = require('log')

local e_callback = errors.new_class('Auth callback failed')

local function authenticate(self, req)
    checks('table', 'table')

    local username = req:param('username')
    local password = req:param('password')

    if username == nil or password == nil then
        return {
            status = 401,
        }
    end

    local res, err = self:_verify(username, password)

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
            username_field = '?string',
            password_field = '?string',
            verify = 'function'})

    local username_field = options.username_field or 'username'
    local password_field = options.username_field or 'password'


    return {
        name = 'local',
        authenticate = authenticate,
        _username_field = username_field,
        _password_field = password_field,
        _verify = options.verify,
    }
end



return {new=new}
