local function urldecode(str)
    str = string.gsub(str, '+', ' ')
    str = string.gsub(str, '%%(%x%x)', function(h)
                          return string.char(tonumber(h, 16))
    end)
    str = string.gsub(str, '\r\n', '\n')
    return str
end

local function urlencode(str)
    if str then
        str = string.gsub(str, '\n', '\r\n')
        str = string.gsub(str, '([^%w-_.~])', function(c)
                              return string.format('%%%02X', string.byte(c))
        end)
    end
    return str
end

local function encode_value(str)
    str = urlencode(str)
    return str:gsub('%%20', '+')
end


local function parse(str)
    local sep = '&'

    local values = {}
    for key, val in str:gmatch(string.format('([^%q=]+)(=*[^%q=]*)', sep, sep)) do
        key = urldecode(key)
        local keys = {}
        key = key:gsub('%[([^%]]*)%]', function(v)
                -- extract keys between balanced brackets
                if string.find(v, "^-?%d+$") then
                    v = tonumber(v)
                else
                    v = urldecode(v)
                end
                table.insert(keys, v)
                return "="
        end)
        key = key:gsub('=+.*$', "")
        key = key:gsub('%s', "_") -- remove spaces in parameter name
        val = val:gsub('^=+', "")

        if not values[key] then
            values[key] = {}
        end
        if #keys > 0 and type(values[key]) ~= 'table' then
            values[key] = {}
        elseif #keys == 0 and type(values[key]) == 'table' then
            values[key] = urldecode(val)
        end

        local t = values[key]
        for i,k in ipairs(keys) do
            if type(t) ~= 'table' then
                t = {}
            end
            if k == "" then
                k = #t+1
            end
            if not t[k] then
                t[k] = {}
            end
            if i == #keys then
                t[k] = urldecode(val)
            end
            t = t[k]
        end
    end

    return values
end

local function build(tab)
    local query = {}
    local sep = '&'

    local keys = {}
    for k in pairs(tab) do
        keys[#keys+1] = k
    end
    table.sort(keys)
    for _,name in ipairs(keys) do
        local value = tab[name]
        name = urlencode(tostring(name))
        if type(value) == 'table' then
            query[#query+1] = M.buildQuery(value, sep, name)
        else
            local value = encode_value(tostring(value))
            if value ~= "" then
                query[#query+1] = string.format('%s=%s', name, value)
            else
                query[#query+1] = name
            end
        end
    end
    return table.concat(query, sep)
end


return {parse=parse, build=build, urlencode=urlencode, urldecode=urldecode}
