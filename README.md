# Tarantool HTTP authentication framework

This module allows you to add HTTP authentication to your tarantool
apps with little effort. It supports various strategies, and you can
easily write your own.

## Supported strategies

- Local (username/password)
- Telegram

## Example


```lua
local static_users = {
    {username='user1', password='foo'},
    {username='user2', password='bar'}
}

-- For most strategies, you should define a `verify` function
-- that checks if such user exists in your app. If it does, then
-- you should return a user object. The auth module doesn't care
-- about its contents, it will be passed along as is.
local function verify(self, username, password)
    for _, user in ipairs(static_users) do
        if user.username == username and user.password == password then
            return user
        end
    end

    return nil
end

-- This function takes your user object and produces a string that
-- will be put into a cookie
local function serialize_user(self, user)
    return user.username
end

-- This function receives a string produced by serialize_user()
-- and turns it back into the user object
local function deserialize_user(self, serialized)
    for _, user in ipairs(static_users) do
        if user.username == serialized then
            return user
        end
    end

    return nil
end

local strategy = local_strategy.new({
    verify = verify,
})

local auth_obj = auth.new(
    {strategy},
    {
        serialize_user = serialize_user,
        deserialize_user = deserialize_user
    }
)

-- Renders the logged-in user's name
local function account_handler(req)
    return {
        status = 200,
        body = req.user.username
    }
end

local httpd = require('http.server').new('127.0.0.1', 8080)

httpd:start()

httpd:route({ path = '/login', method = 'POST' },
    auth_obj:authenticate('local'))

-- This route will be protected with authentication
httpd:route({ path = '/account', method = 'GET' },
    auth.chain(auth_obj:auth_required(), account_handler))
```
