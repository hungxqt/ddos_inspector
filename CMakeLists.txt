cmake_minimum_required(VERSION 3.16)
project(ddos_inspector VERSION 1.0.0 LANGUAGES CXX)

# Function to read environment variables from .env file
function(load_env_file)
    set(ENV_FILE "${CMAKE_CURRENT_SOURCE_DIR}/.env")
    if(EXISTS "${ENV_FILE}")
        message(STATUS "Loading configuration from ${ENV_FILE}")
        file(STRINGS "${ENV_FILE}" ENV_CONTENTS)
        foreach(line ${ENV_CONTENTS})
            # Skip comments and empty lines
            if(NOT line MATCHES "^#" AND NOT line STREQUAL "")
                # Parse key=value pairs
                if(line MATCHES "^([^=]+)=(.*)$")
                    set(key "${CMAKE_MATCH_1}")
                    set(value "${CMAKE_MATCH_2}")
                    # Remove quotes if present
                    string(REGEX REPLACE "^[\"']|[\"']$" "" value "${value}")
                    # Set as environment variable for this CMake run
                    set(ENV{${key}} "${value}")
                    message(STATUS "  Set ${key}=${value}")
                endif()
            endif()
        endforeach()
    else()
        message(STATUS "No .env file found at ${ENV_FILE}, using system defaults")
    endif()
endfunction()

# Load environment variables from .env file
load_env_file()

# Use GNUInstallDirs for standard installation paths
include(GNUInstallDirs)

# Set C++ standard to C++20 for modern features and compatibility with Snort 3.8.1.0
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Generate compile_commands.json for IDE support (clangd, etc.)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Enable testing support
enable_testing()

# Include CDash support
include(CTest)

# Build type specific flags
set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -DDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG -march=native -flto")

# Find required packages
find_package(Threads REQUIRED)
find_package(PkgConfig QUIET)

# Find libcap for capability management in firewall_action
if(PkgConfig_FOUND)
    pkg_check_modules(CAP REQUIRED libcap)
    if(CAP_FOUND)
        message(STATUS "Found libcap: ${CAP_LIBRARIES}")
    endif()
else()
    # Fallback for systems without pkg-config
    find_library(CAP_LIBRARIES cap)
    if(CAP_LIBRARIES)
        set(CAP_FOUND TRUE)
        message(STATUS "Found libcap: ${CAP_LIBRARIES}")
    else()
        message(FATAL_ERROR "libcap is required but not found")
    endif()
endif()

# Function to find Snort 3 installation
function(find_snort3)
    # First try to use SNORT_INCLUDE_DIR from .env file
    if(DEFINED ENV{SNORT_INCLUDE_DIR} AND EXISTS $ENV{SNORT_INCLUDE_DIR})
        set(SNORT3_INCLUDE_DIR $ENV{SNORT_INCLUDE_DIR} PARENT_SCOPE)
        set(SNORT3_INCLUDE_DIR_LOCAL $ENV{SNORT_INCLUDE_DIR})
        message(STATUS "Using Snort include directory from .env: ${SNORT3_INCLUDE_DIR_LOCAL}")
    # Fallback to SNORT3_INCLUDE_DIR environment variable (legacy)
    elseif(DEFINED ENV{SNORT3_INCLUDE_DIR} AND EXISTS $ENV{SNORT3_INCLUDE_DIR})
        set(SNORT3_INCLUDE_DIR $ENV{SNORT3_INCLUDE_DIR} PARENT_SCOPE)
        set(SNORT3_INCLUDE_DIR_LOCAL $ENV{SNORT3_INCLUDE_DIR})
        message(STATUS "Using Snort include directory from SNORT3_INCLUDE_DIR: ${SNORT3_INCLUDE_DIR_LOCAL}")
    # Search common locations
    else()
        set(SNORT_SEARCH_PATHS
            "/usr/local/snort3/include/snort"
            "/usr/local/include/snort"
            "/usr/include/snort"
            "/opt/snort3/include/snort"
            "/usr/include/snort3"
            "/usr/local/include/snort3"
        )
        
        set(SNORT3_INCLUDE_DIR_LOCAL "")
        foreach(path ${SNORT_SEARCH_PATHS})
            if(EXISTS "${path}")
                set(SNORT3_INCLUDE_DIR_LOCAL "${path}")
                set(SNORT3_INCLUDE_DIR "${path}" PARENT_SCOPE)
                message(STATUS "Found Snort headers at: ${path}")
                break()
            endif()
        endforeach()
        
        if(NOT SNORT3_INCLUDE_DIR_LOCAL)
            message(FATAL_ERROR "Snort 3 headers not found. Searched paths: ${SNORT_SEARCH_PATHS}. Please set SNORT_INCLUDE_DIR in .env file or install Snort 3 development headers.")
        endif()
    endif()
    
    # Verify Snort 3 installation
    if(EXISTS ${SNORT3_INCLUDE_DIR_LOCAL})
        message(STATUS "Using Snort 3 headers at: ${SNORT3_INCLUDE_DIR_LOCAL}")
        
        # Check for specific Snort 3.8.1.0 headers to ensure compatibility
        if(EXISTS "${SNORT3_INCLUDE_DIR_LOCAL}/framework/snort_api.h")
            message(STATUS "Snort 3 API headers found - build should be compatible")
        else()
            message(WARNING "Snort 3 API headers missing at ${SNORT3_INCLUDE_DIR_LOCAL}/framework/snort_api.h - build may fail")
        endif()
    else()
        message(FATAL_ERROR "Snort 3 headers not found at ${SNORT3_INCLUDE_DIR_LOCAL}. Please install Snort 3.8.1.0 or set SNORT_INCLUDE_DIR in .env file")
    endif()
endfunction()

# Find Snort 3
find_snort3()

# Collect source files
file(GLOB SOURCES "src/*.cpp")
list(REMOVE_ITEM SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/src/ddos_inspector.cpp")

# Core library for shared functionality
add_library(ddos_core STATIC ${SOURCES})

# Set target properties for core library
target_include_directories(ddos_core
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    PRIVATE
        ${SNORT3_INCLUDE_DIR}
)

target_compile_definitions(ddos_core
    PRIVATE
        _GLIBCXX_USE_CXX11_ABI=1
)

target_compile_options(ddos_core
    PRIVATE
        $<$<CXX_COMPILER_ID:GNU,Clang>:
            -Wall -Wextra -Wpedantic
            -Wno-unused-parameter
            -fPIC
            -fvisibility=hidden
        >
)

target_link_libraries(ddos_core 
    PUBLIC 
        Threads::Threads
        ${CAP_LIBRARIES}
)

# Main Snort 3 plugin
add_library(ddos_inspector SHARED src/ddos_inspector.cpp)

target_include_directories(ddos_inspector
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${SNORT3_INCLUDE_DIR}
)

target_compile_definitions(ddos_inspector 
    PRIVATE
        _GLIBCXX_USE_CXX11_ABI=1
        SO_PUBLIC=
)

target_compile_options(ddos_inspector 
    PRIVATE
        $<$<CXX_COMPILER_ID:GNU,Clang>:
            -Wall -Wextra -Wpedantic
            -Wno-unused-parameter
            -fvisibility=default
        >
)

target_link_libraries(ddos_inspector 
    PRIVATE 
        ddos_core
        Threads::Threads
)

# Plugin properties for Snort 3.8.1.0 compatibility
set_target_properties(ddos_inspector PROPERTIES
    OUTPUT_NAME "ddos_inspector"
    PREFIX "lib"
    SUFFIX ".so"
    CXX_VISIBILITY_PRESET default
    POSITION_INDEPENDENT_CODE ON
)

# Function to get plugin installation path
function(get_plugin_install_path)
    # Use SNORT_PLUGIN_PATH from .env file if available
    if(DEFINED ENV{SNORT_PLUGIN_PATH})
        set(PLUGIN_INSTALL_PATH $ENV{SNORT_PLUGIN_PATH} PARENT_SCOPE)
        message(STATUS "Using plugin install path from .env: $ENV{SNORT_PLUGIN_PATH}")
    else()
        # Default fallback
        set(PLUGIN_INSTALL_PATH "/usr/local/lib/snort3_extra_plugins" PARENT_SCOPE)
        message(STATUS "Using default plugin install path: /usr/local/lib/snort3_extra_plugins")
    endif()
endfunction()

# Get plugin installation path
get_plugin_install_path()

# Install plugin to Snort directory
install(TARGETS ddos_inspector 
    LIBRARY DESTINATION ${PLUGIN_INSTALL_PATH})

# Function to get config installation path
function(get_config_install_path)
    # Use SNORT_CONFIG_PATH from .env file if available
    if(DEFINED ENV{SNORT_CONFIG_PATH})
        set(CONFIG_INSTALL_PATH $ENV{SNORT_CONFIG_PATH} PARENT_SCOPE)
        message(STATUS "Using config install path from .env: $ENV{SNORT_CONFIG_PATH}")
    else()
        # Default fallback
        set(CONFIG_INSTALL_PATH "/etc/snort" PARENT_SCOPE)
        message(STATUS "Using default config install path: /etc/snort")
    endif()
endfunction()

# Get config installation path
get_config_install_path()

# Install configuration files
install(FILES snort_ddos_config.lua 
    DESTINATION ${CONFIG_INSTALL_PATH})

# Testing framework setup
if(BUILD_TESTING)
    # Try to find Google Test
    find_package(GTest QUIET)
    
    if(NOT GTest_FOUND)
        message(STATUS "Google Test not found, attempting to build from source")
        include(FetchContent)
        FetchContent_Declare(
            googletest
            URL https://github.com/google/googletest/archive/v1.15.2.zip
            DOWNLOAD_EXTRACT_TIMESTAMP true
        )
        # Set gtest to build shared libraries as false to avoid issues
        set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
        set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
        FetchContent_MakeAvailable(googletest)
    endif()

    # Function to create test targets
    function(add_component_test test_name source_file)
        add_executable(${test_name} ${source_file})
        target_link_libraries(${test_name} 
            PRIVATE 
                ddos_core 
                gtest 
                gtest_main 
                Threads::Threads
        )
        target_compile_definitions(${test_name} PRIVATE TESTING)
        add_test(NAME ${test_name} COMMAND ${test_name})
    endfunction()

    # Create test executables
    add_component_test(unit_tests tests/unit_tests.cpp)
    add_component_test(test_stats_engine tests/test_stats_engine.cpp)
    add_component_test(test_behavior_tracker tests/test_behavior_tracker.cpp)
    add_component_test(test_firewall_action tests/test_firewall_action.cpp)

    # Realistic attack simulation tests (conditional)
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_realistic_attacks.cpp")
        add_component_test(test_realistic_attacks tests/test_realistic_attacks.cpp)
    endif()

    # Normal traffic simulation tests (conditional)
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_normal_traffic.cpp")
        add_component_test(test_normal_traffic tests/test_normal_traffic.cpp)
    endif()

    # Advanced detection tests (conditional)
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_advanced_detection.cpp")
        add_component_test(test_advanced_detection tests/test_advanced_detection.cpp)
    endif()

    # Classification tests (conditional)
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_classification.cpp")
        add_component_test(test_classification tests/test_classification.cpp)
    endif()

    # Add test aliases for convenience
    add_test(NAME AllTests COMMAND unit_tests)
    add_test(NAME StatsEngineTests COMMAND test_stats_engine)
    add_test(NAME BehaviorTrackerTests COMMAND test_behavior_tracker)
    add_test(NAME FirewallActionTests COMMAND test_firewall_action)
endif()

# Package configuration
set(CPACK_PACKAGE_NAME "ddos-inspector")
set(CPACK_PACKAGE_VERSION "1.0.0")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Advanced DDoS Inspector Plugin for Snort 3.8.1.0")
set(CPACK_PACKAGE_VENDOR "ADHHP Team")
set(CPACK_GENERATOR "DEB;RPM;TGZ")

include(CPack)

# Print build configuration summary
message(STATUS "")
message(STATUS "DDoS Inspector Build Configuration:")
message(STATUS "  Build Type: ${CMAKE_BUILD_TYPE}")
message(STATUS "  C++ Standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "  Snort 3 Include: ${SNORT3_INCLUDE_DIR}")
message(STATUS "  Testing: ${BUILD_TESTING}")
message(STATUS "  Install Prefix: ${CMAKE_INSTALL_PREFIX}")
message(STATUS "")
