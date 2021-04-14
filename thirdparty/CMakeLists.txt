cmake_minimum_required(VERSION 3.1.2)

# LIBYAML
set(LIBYAML_DIR ${CMAKE_CURRENT_SOURCE_DIR}/libyaml)
aux_source_directory(${LIBYAML_DIR}/src LIBYAML_SOURCE_FILES)

add_library(yaml STATIC ${LIBYAML_SOURCE_FILES})
target_include_directories(yaml
    PUBLIC ${LIBYAML_DIR}/include)
target_compile_definitions(yaml
    PRIVATE HAVE_CONFIG_H)


## LIBCYAML
#set(LIBCYAML_DIR ${CMAKE_CURRENT_SOURCE_DIR}/libcyaml)
#aux_source_directory(${LIBCYAML_DIR}/src LIBCYAML_SOURCE_FILES)
#
#add_library(cyaml STATIC ${LIBCYAML_SOURCE_FILES})
#target_compile_definitions(cyaml
#    PRIVATE VERSION_MAJOR=1
#    PRIVATE VERSION_MINOR=1
#    PRIVATE VERSION_PATCH=0
#)
## Dependency libyaml
#target_link_libraries(cyaml 
#    PUBLIC yaml)
#target_include_directories(cyaml
#    PUBLIC ${LIBCYAML_DIR}/include)


# LIBEVENT 
add_library(event INTERFACE)

if (DOUBLE_LIBEVENT_BINARY_DIR AND DOUBLE_LIBEVENT_INCLUDE_DIR)
    # libevent core and extra 
    find_library(libevent_shared
        NAMES libevent.so 
        PATHS ${DOUBLE_LIBEVENT_BINARY_DIR}
        NO_DEFAULT_PATH
    )
    if (${libevent_shared} STREQUAL libevent_shared-NOTFOUND)
        message(FATAL_ERROR "libevent.so could not be found '${DOUBLE_LIBEVENT_BINARY_DIR}'")
    endif()

    # libevent openssl
    find_library(libevent_openssl_shared
        NAMES libevent_openssl.so
        PATHS ${DOUBLE_LIBEVENT_BINARY_DIR}
        NO_DEFAULT_PATH
    )
    if (${libevent_openssl_shared} STREQUAL libevent_openssl_shared-NOTFOUND)
        message(FATAL_ERROR "libevent_openssl.so could not be found '${DOUBLE_LIBEVENT_BINARY_DIR}'")
    endif()

    # header files
    find_path(libevent_include_dir
        NAMES event2
        PATHS ${DOUBLE_LIBEVENT_INCLUDE_DIR}
        NO_DEFAULT_PATH
    )
    if (${libevent_include_dir} STREQUAL libevent_include_dir-NOTFOUND)
        message(FATAL_ERROR "libevent header files could not be found '${DOUBLE_LIBEVENT_INCLUDE_DIR}'")
    endif()

    set(LIBEVENT_INCLUDE_DIRS ${libevent_include_dir})
    set(LIBEVENT_SHARED_LIBRARIES ${libevent_shared} ${libevent_openssl_shared})

else()
    find_package(Libevent QUIET)
    message(STATUS "OOOKK")
    if (NOT Libevent_FOUND)
        message(FATAL_ERROR "Find package 'libevent' failed. If you already installed 'libevent', use 'DOUBLE_LIBEVENT_BINARY_DIR' and 'DOUBLE_LIBEVENT_INCLUDE_DIR' to specify the directory") 
    endif()
    target_include_directories(event
        INTERFACE ${LIBEVENT_INCLUDE_DIRS})
    target_link_libraries(event
        INTERFACE libevent.so
    event_shared event_openssl_shared)

    message(STATUS "Libevent include: ${LIBEVENT_INCLUDE_DIRS}")
    message(STATUS "Libevent lib: ${event_openssl_shared}")
endif()


# LIBSSL
find_package(OpenSSL REQUIRED)
add_library(ssl SHARED IMPORTED)

set_target_properties(ssl PROPERTIES
    IMPORTED_LOCATION "${OPENSSL_LIBRARIES}"
    BUILD_INTERFACE "${OPENSSL_INCLUDE_DIR}"
    #INTERFACE_LINK_LIBRARIES "-lpthread;event_core_shared"
)

#add_library(ssl INTERFACE)
#target_include_directories(ssl SYSTEM INTERFACE
#    $<BUILD_INTERFACE:${OPENSSL_INCLUDE_DIR}>
#    )
##target_include_directories(ssl
##    INTERFACE ${OPENSSL_INCLUDE_DIR})
#target_link_libraries(ssl
#    INTERFACE ${OPENSSL_LIBRARIES})
message(STATUS "OpenSSL include: ${OPENSSL_INCLUDE_DIR}")
message(STATUS "OpenSSL lib: ${OPENSSL_LIBRARIES}")
