cmake_minimum_required(VERSION 4.0)
project(adbcat C)

set(CMAKE_C_STANDARD 11)

find_package(PkgConfig QUIET)
if (PKG_CONFIG_FOUND)
    pkg_search_module(LIBEVENT libevent)
    if (LIBEVENT_FOUND)
        message(STATUS "Found libevent ${LIBEVENT_FOUND}")
        message(STATUS "libevent inc : ${LIBEVENT_INCLUDE_DIRS}")
        message(STATUS "libevent lib : ${LIBEVENT_LIBRARIES}")
        message(STATUS "libevent tls : ${LIBEVENT_OPENSSL_LIBRARIES}")
    endif()
endif()

set(LIBEVENT_STATIC_LINK TRUE)

find_package(OpenSSL REQUIRED)

add_executable(${PROJECT_NAME}
        gateway.c
        utils.c
        hashtable.c
        client.c
        server.c
        main.c)

target_link_directories(${PROJECT_NAME} PUBLIC ${LIBEVENT_INCLUDE_DIRS}/../lib)

target_include_directories(${PROJECT_NAME} PRIVATE ${LIBEVENT_INCLUDE_DIRS} ${CMAKE_CURRENT_SOURCE_DIR})
if (LINUX)
    set(ADDL_LIBS "bsd")
else()
    set(ADDL_LIBS "")
endif()
target_link_libraries(${PROJECT_NAME} PUBLIC ${LIBEVENT_OPENSSL_LIBRARIES} event_openssl event ${ADDL_LIBS} OpenSSL::SSL OpenSSL::Crypto)
