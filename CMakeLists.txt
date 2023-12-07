cmake_minimum_required(VERSION 3.25)
project(adbcat C)

set(CMAKE_C_STANDARD 11)

find_package(PkgConfig QUIET)
if (PKG_CONFIG_FOUND)
    pkg_search_module(LIBEVENT libevent)
    if (LIBEVENT_FOUND)
        message(STATUS "Found libevent ${LIBEVENT_FOUND}")
        message(STATUS "libevent inc : ${LIBEVENT_INCLUDE_DIRS}")
        message(STATUS "libevent lib : ${LIBEVENT_LIBRARIES}")
    endif()
endif()

set(LIBEVENT_STATIC_LINK TRUE)

add_executable(${PROJECT_NAME} main.c)

target_link_directories(${PROJECT_NAME} PUBLIC ${LIBEVENT_INCLUDE_DIRS}/../lib)

target_include_directories(${PROJECT_NAME} PRIVATE ${LIBEVENT_INCLUDE_DIRS} ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(${PROJECT_NAME} PUBLIC ${LIBEVENT_LIBRARIES})
