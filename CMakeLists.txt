cmake_minimum_required(VERSION 3.1.2 FATAL_ERROR)

project(double VERSION 1.0) 
include(CheckSymbolExists)
include(CheckIncludeFile)

option(BUILD_TESTING OFF)
#set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

if(NOT DOUBLE_INSTALL_PATH)
    set(DOUBLE_INSTALL_PATH ${CMAKE_INSTALL_PREFIX}/double)
endif()

set(DOUBLE_PID_PATH         ${DOUBLE_INSTALL_PATH}/double.pid)
set(DOUBLE_CONFIG_PATH      ${DOUBLE_INSTALL_PATH}/double.conf)
set(DOUBLE_ERRORLOG_PATH    ${DOUBLE_INSTALL_PATH}/error.log)
set(DOUBLE_ACCESSLOG_PATH   ${DOUBLE_INSTALL_PATH}/access.log)

check_symbol_exists(__GNU_LIBRARY__ "features.h" DOUBLE_HAVE_GLIBC)
if (NOT DOUBLE_HAVE_GLIBC)
    list(APPEND DOUBLE_COMPILE_DEFINES _POSIX_C_SOURCE=200809L)
    set(CMAKE_REQUIRED_DEFINITIONS -D _POSIX_C_SOURCE=200809L)
else()
    list(APPEND DOUBLE_COMPILE_DEFINES _GNU_SOURCE=1) 
    set(CMAKE_REQUIRED_DEFINITIONS -D _GNU_SOURCE=1)
endif()

check_include_file(sys/queue.h DOUBLE_HAVE_SYS_QUEUE_H)
check_symbol_exists(strcasecmp "string.h" DOUBLE_HAVE_STRCASECMP)
check_symbol_exists(strsep "string.h" DOUBLE_HAVE_STRSEP)

# Generate the configure header file 
configure_file(
    ${PROJECT_SOURCE_DIR}/dbl_autoconfig.h.cmake
    ${PROJECT_BINARY_DIR}/include/dbl_autoconfig.h)

# Generate the application configure file 
configure_file(
    ${PROJECT_SOURCE_DIR}/config.yaml.cmake
    ${PROJECT_BINARY_DIR}/double.conf)

# Generate the application 
aux_source_directory(src PROJECT_SOURCE_FILES)

add_executable(double ${PROJECT_SOURCE_FILES}) 
target_compile_options(double 
    PRIVATE -std=c99 -Wall) 

target_compile_definitions(double
    PRIVATE ${DOUBLE_COMPILE_DEFINES})

target_include_directories(double 
    PRIVATE
    "src/"
    "${PROJECT_BINARY_DIR}/include")

# Third party libraries
add_subdirectory(thirdparty)
target_link_libraries(double
    PRIVATE
    ssl
    event
    yaml)

install(
    FILES 
    ${CMAKE_CURRENT_BINARY_DIR}/double.conf
    DESTINATION ${DOUBLE_INSTALL_PATH}
    )

install(
    TARGETS double 
    DESTINATION "${DOUBLE_INSTALL_PATH}"
    )

message(STATUS  "CMAKE_C_COMPILER               ${CMAKE_C_COMPILER} (${CMAKE_C_COMPILER_ID}-${CMAKE_C_COMPILER_VERSION})")
message(STATUS  "CMAKE_BUILD_TYPE:              ${CMAKE_BUILD_TYPE}")
message(STATUS  "CMAKE_INSTALL_PREFIX           ${CMAKE_INSTALL_PREFIX}")
message(STATUS  "DOUBLE_INSTALL_PATH            ${DOUBLE_INSTALL_PATH}")
message(STATUS  "DOUBLE_CONFIG_PATH             ${DOUBLE_CONFIG_PATH}")
message(STATUS  "DOUBLE_PID_PATH                ${DOUBLE_PID_PATH}")
