cmake_minimum_required(VERSION 2.8 FATAL_ERROR)

project(auth C)

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})
set(CMAKE_SKIP_INSTALL_ALL_DEPENDENCY TRUE)

# Find Tarantool and Lua dependecies
set(TARANTOOL_FIND_REQUIRED ON)
find_package(Tarantool)
include_directories(${TARANTOOL_INCLUDE_DIRS})

file(GLOB_RECURSE LUA_FILES
  "${CMAKE_CURRENT_SOURCE_DIR}/auth.lua"
  "${CMAKE_CURRENT_SOURCE_DIR}/auth/strategy/*.lua"
)

## API doc ####################################################################
###############################################################################

set(DOC_OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/doc/index.html)

if(BUILD_DOC)
  set(LDOC_FIND_REQUIRED ON)
endif()
find_package(Ldoc)

add_custom_command(
  OUTPUT DOC_OUTPUT
  COMMAND ${LDOC} -t "${PROJECT_NAME}-${version}" -p "${PROJECT_NAME} (${version})" --all .
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  DEPENDS ${LUA_FILES}
  COMMENT "Building API documentation"
  VERBATIM
)

if(LDOC_FOUND)
  add_custom_target(doc ALL
    DEPENDS DOC_OUTPUT)
else()
  add_custom_target(doc
    DEPENDS DOC_OUTPUT)
endif()

## GraphQL schema #############################################################
###############################################################################

add_custom_command(
  OUTPUT ${CMAKE_CURRENT_SOURCE_DIR}/doc/schema.graphql
  COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/fetch-schema.sh
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  DEPENDS ${LUA_FILES}
  COMMENT "Fetching GraphQL schema"
)
add_custom_target(schema
  DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/doc/schema.graphql
)

## Testing ####################################################################
###############################################################################

enable_testing()

add_test(
  NAME lint
  COMMAND luacheck auth-scm-1.rockspec
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

add_test(
  NAME test_unit
  COMMAND ${TARANTOOL} ${CMAKE_CURRENT_SOURCE_DIR}/taptest.lua
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

add_test(
  NAME test_integration
  COMMAND pytest -v
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)

## Install ####################################################################
###############################################################################

install(
  FILES ${CMAKE_CURRENT_SOURCE_DIR}/auth.lua
  DESTINATION ${TARANTOOL_INSTALL_LUADIR}/
)

install(
  DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/auth
            ${CMAKE_CURRENT_SOURCE_DIR}/${PROJECT_NAME}
  DESTINATION ${TARANTOOL_INSTALL_LUADIR}/
)
