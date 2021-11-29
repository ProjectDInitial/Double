set(LIBYAML_RESOURCE_DIR        ${CMAKE_CURRENT_LIST_DIR}/libyaml)
set(LIBHTTP_PARSER_RESOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/libhttp_parser)

# libyaml v0.2.5
aux_source_directory(${LIBYAML_RESOURCE_DIR}/src LIBYAML_SOURCE_FILES)
add_library(yaml STATIC ${LIBYAML_SOURCE_FILES})
target_include_directories(yaml
    PUBLIC ${LIBYAML_RESOURCE_DIR}/include)
target_compile_definitions(yaml
    PRIVATE HAVE_CONFIG_H)

# nodejs/http-parser v2.9.4
add_library(http_parser STATIC ${LIBHTTP_PARSER_RESOURCE_DIR}/http_parser.c)
target_include_directories(http_parser
    PUBLIC ${LIBHTTP_PARSER_RESOURCE_DIR})
target_compile_definitions(http_parser
    PRIVATE HTTP_PARSER_STRICT=0    #Compile with -DHTTP_PARSER_STRICT=0 to make less checks, but run faster 
    PRIVATE HTTP_MAX_HEADER_SIZE=0x7fffffff)

# Openssl
find_package(OpenSSL REQUIRED)
add_library(ssl INTERFACE) 
target_link_libraries(ssl
    INTERFACE ${OPENSSL_SSL_LIBRARY})
target_include_directories(ssl
    INTERFACE ${OPENSSL_INCLUDE_DIR})
add_library(crypto INTERFACE)
target_link_libraries(crypto
    INTERFACE ${OPENSSL_CRYPTO_LIBRARY})
target_include_directories(crypto
    INTERFACE ${OPENSSL_INCLUDE_DIR})

# libevent (version >= 2.1.10) 
add_library(event INTERFACE)
if (DOUBLE_LIBEVENT_INCLUDE_DIR AND DOUBLE_LIBEVENT_BINARY_DIR)
    find_library(DOUBLE_LIBEVENT_CORE_SHARED
        NAMES libevent_core.so
        PATHS ${DOUBLE_LIBEVENT_BINARY_DIR}
        NO_DEFAULT_PATH)
    if (${DOUBLE_LIBEVENT_CORE_SHARED} STREQUAL DOUBLE_LIBEVENT_CORE-NOTFOUND)
        message(FATAL_ERROR "libevent_core.so could not be found on '${DOUBLE_LIBEVENT_BINARY_DIR}'")
    endif()
    add_library(event_core SHARED IMPORTED)
    set_target_properties(event_core PROPERTIES
        IMPORTED_LOCATION   ${DOUBLE_LIBEVENT_CORE_SHARED})

    find_library(DOUBLE_LIBEVENT_OPENSSL_SHARED
        NAMES libevent_openssl.so
        PATHS ${DOUBLE_LIBEVENT_BINARY_DIR}
        NO_DEFAULT_PATH)
    if (${DOUBLE_LIBEVENT_OPENSSL_SHARED} STREQUAL DOUBLE_LIBEVENT_OPENSSL_SHARED-NOTFOUND)
        message(FATAL_ERROR "libevent_openssl.so could not be found on '${DOUBLE_LIBEVENT_BINARY_DIR}'")
    endif()
    add_library(event_openssl SHARED IMPORTED)
    set_target_properties(event_openssl PROPERTIES
        IMPORTED_LOCATION   ${DOUBLE_LIBEVENT_OPENSSL_SHARED})
    
    # Check the directory 'event2' is exists in the directory
    find_path(libevent_include_dir
        NAMES event2
        PATHS ${DOUBLE_LIBEVENT_INCLUDE_DIR}
        NO_DEFAULT_PATH)
    if (libevent_include_dir STREQUAL libevent_include_dir-NOTFOUND)
        message(FATAL_ERROR "libevent include directory 'event2' could not be found on '${DOUBLE_LIBEVENT_INCLUDE_DIR}'")
    endif()
    target_link_libraries(event
        INTERFACE event_core event_openssl)
    target_include_directories(event
        INTERFACE ${DOUBLE_LIBEVENT_INCLUDE_DIR})
else()
    find_package(Libevent)
    if (NOT Libevent_FOUND)
        message(FATAL_ERROR "libevent not found. If you already installed libevent, use 'DOUBLE_LIBEVENT_BINARY_DIR' and 'DOUBLE_LIBEVENT_INCLUDE_DIR' to set the directory") 
    endif()
    target_include_directories(event
        INTERFACE ${LIBEVENT_INCLUDE_DIRS})
    target_link_libraries(event
        INTERFACE event_core_shared event_openssl_shared)
endif()
