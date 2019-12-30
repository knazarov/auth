package = 'auth'
version = 'scm-1'
source  = {
    url = '/dev/null',
}

dependencies = {
    'tarantool',
    'lua >= 5.1',
    'errors',
    'checks'
}

build = {
    type = 'cmake',
    variables = {
        version = 'scm-1',
        BUILD_DOC = '$(BUILD_DOC)',
        TARANTOOL_DIR = '$(TARANTOOL_DIR)',
        TARANTOOL_INSTALL_LIBDIR = '$(LIBDIR)',
        TARANTOOL_INSTALL_LUADIR = '$(LUADIR)',
    }
}
