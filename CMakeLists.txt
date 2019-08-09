cmake_minimum_required(VERSION 3.1.2 FATAL_ERROR)

project(double VERSION 1.0) 
include(CheckSymbolExists)

option(BUILD_TESTING OFF)
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

set(DOUBLE_INSTALL_PATH     ${CMAKE_INSTALL_PREFIX}/double)
set(DOUBLE_PID_PATH         ${DOUBLE_INSTALL_PATH}/double.pid)
set(DOUBLE_CONFIG_PATH      ${DOUBLE_INSTALL_PATH}/double.conf)

# If error log file is not specified
if(NOT DOUBLE_ERROR_LOG)
    set(DOUBLE_ERROR_LOG ${DOUBLE_INSTALL_PATH}/error.log)
endif()

# If access log file is not specified
if(NOT DOUBLE_ACCESS_LOG)
    set(DOUBLE_ACCESS_LOG ${DOUBLE_INSTALL_PATH}/access.log)
endif()


check_symbol_exists(__GNU_LIBRARY__ "features.h" DOUBLE_HAVE_GNULIBC)
if (NOT DOUBLE_HAVE_GNULIBC)
    message(FATAL_ERROR "The C runtime library is not GNU C library")
endif()
add_compile_definitions(_GNU_SOURCE=1)

# Use ISO C99
add_compile_options(-std=c99)


# Generate the configure header 
configure_file(
    ${PROJECT_SOURCE_DIR}/src/double-config.h.in
    ${PROJECT_BINARY_DIR}/include/double-config.h
)

# Generate the application configure file 
configure_file(
    ${PROJECT_SOURCE_DIR}/double.conf.in
    ${PROJECT_BINARY_DIR}/double.conf
    )

# Generate the application 
aux_source_directory(src PROJECT_SOURCE_FILES)
add_executable(double ${PROJECT_SOURCE_FILES}) 
# include configure header
target_include_directories(double 
    PRIVATE "${PROJECT_BINARY_DIR}/include")

# Add third-party dependent libraries
add_subdirectory(thirdparty)
target_link_libraries(double
    PRIVATE ssl event cyaml)


install(
    FILES 
    ${CMAKE_CURRENT_BINARY_DIR}/double.conf
    DESTINATION "${DOUBLE_INSTALL_PATH}"
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
