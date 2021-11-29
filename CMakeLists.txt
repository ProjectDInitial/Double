cmake_minimum_required(VERSION 3.1.2 FATAL_ERROR)

project(double VERSION 1.0) 
include(CheckSymbolExists)
include(CheckIncludeFile)
include(CheckTypeSize)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

if(NOT DOUBLE_INSTALL_PREFIX)
    set(DOUBLE_INSTALL_PREFIX ${CMAKE_INSTALL_PREFIX}/double)
endif()

set(DOUBLE_PID_PATH         ${DOUBLE_INSTALL_PREFIX}/double.pid)
set(DOUBLE_CONFIG_PATH      ${DOUBLE_INSTALL_PREFIX}/double.conf)
set(DOUBLE_ERRORLOG_PATH    ${DOUBLE_INSTALL_PREFIX}/error.log)
set(DOUBLE_ACCESSLOG_PATH   ${DOUBLE_INSTALL_PREFIX}/access.log)

CHECK_SYMBOL_EXISTS(__GNU_LIBRARY__ "features.h" DOUBLE_HAVE_GLIBC)
if (DOUBLE_HAVE_GLIBC)
    list(APPEND DOUBLE_COMPILE_DEFINES _GNU_SOURCE) 
    set(CMAKE_REQUIRED_DEFINITIONS -D _GNU_SOURCE)
else()
    list(APPEND DOUBLE_COMPILE_DEFINES _POSIX_C_SOURCE=200809L)
    set(CMAKE_REQUIRED_DEFINITIONS -D _POSIX_C_SOURCE=200809L)
endif()

CHECK_SYMBOL_EXISTS(__USE_POSIX2 "features.h" DOUBLE_HAVE_POSIX2)
if (NOT DOUBLE_HAVE_POSIX2)
    message(FATAL_ERROR "'POSIX2' is required but not found")
endif()

CHECK_INCLUDE_FILE(sys/queue.h DOUBLE_HAVE_SYS_QUEUE_H)
CHECK_SYMBOL_EXISTS(strcasecmp "string.h" DOUBLE_HAVE_STRCASECMP)
CHECK_SYMBOL_EXISTS(strsep "string.h" DOUBLE_HAVE_STRSEP)
CHECK_TYPE_SIZE(size_t DOUBLE_SIZEOF_SIZE_T)
CHECK_TYPE_SIZE(int DOUBLE_SIZEOF_INT)
CHECK_TYPE_SIZE(time_t DOUBLE_SIZEOF_TIME_T)

# Generate the configure header file 
configure_file(
    ${PROJECT_SOURCE_DIR}/src/dbl_autoconfig.h.cmake
    ${PROJECT_BINARY_DIR}/include/dbl_autoconfig.h)

# Generate the application configure file 
configure_file(
    ${PROJECT_SOURCE_DIR}/double.conf.cmake
    ${PROJECT_BINARY_DIR}/double.conf)

aux_source_directory(src PROJECT_SOURCE_FILES)
aux_source_directory(src/modules PROJECT_SOURCE_FILES)
add_executable(double ${PROJECT_SOURCE_FILES}) 
add_subdirectory(thirdparty)
target_compile_options(double 
    PRIVATE -std=c99 -Wall) 
target_compile_definitions(double
    PRIVATE ${DOUBLE_COMPILE_DEFINES})
target_include_directories(double 
    PRIVATE
    "src/"
    "${PROJECT_BINARY_DIR}/include")
target_include_directories(double 
    PRIVATE src src/modules)
target_link_libraries(double
    PRIVATE event ssl crypto yaml http_parser)

install(
    FILES 
    ${CMAKE_CURRENT_BINARY_DIR}/double.conf
    DESTINATION ${DOUBLE_INSTALL_PREFIX}
    )
install(
    TARGETS double 
    DESTINATION "${DOUBLE_INSTALL_PREFIX}"
    )

message(STATUS  "CMAKE_C_COMPILER               ${CMAKE_C_COMPILER} (${CMAKE_C_COMPILER_ID}-${CMAKE_C_COMPILER_VERSION})")
message(STATUS  "CMAKE_BUILD_TYPE               ${CMAKE_BUILD_TYPE}")
message(STATUS  "CMAKE_INSTALL_PREFIX           ${CMAKE_INSTALL_PREFIX}")
message(STATUS  "DOUBLE_INSTALL_PREFIX          ${DOUBLE_INSTALL_PREFIX}")
message(STATUS  "DOUBLE_CONFIG_PATH             ${DOUBLE_CONFIG_PATH}")
message(STATUS  "DOUBLE_PID_PATH                ${DOUBLE_PID_PATH}")
