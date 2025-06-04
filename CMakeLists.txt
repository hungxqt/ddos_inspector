cmake_minimum_required(VERSION 3.16)
project(ddos_inspector VERSION 1.0.0 LANGUAGES CXX)

# Set C++ standard to C++20 for modern features and compatibility with Snort 3.8.1.0
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Enable testing support
enable_testing()

# Include CDash support
include(CTest)

# Compiler-specific optimizations
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(
        -Wall -Wextra -Wpedantic
        -Wno-unused-parameter
        -fPIC
        -fvisibility=hidden
    )
endif()

# Build type specific flags
set(CMAKE_CXX_FLAGS_DEBUG "-g -O0 -DDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG -march=native -flto")

# Find required packages
find_package(Threads REQUIRED)
find_package(PkgConfig QUIET)

# Configure Snort 3 paths - support both environment variable and default
if(DEFINED ENV{SNORT3_INCLUDE_DIR})
    set(SNORT3_INCLUDE_DIR $ENV{SNORT3_INCLUDE_DIR})
else()
    set(SNORT3_INCLUDE_DIR "/usr/local/snort3/include/snort")
endif()

# Verify Snort 3 installation
if(EXISTS ${SNORT3_INCLUDE_DIR})
    message(STATUS "Found Snort 3 headers at: ${SNORT3_INCLUDE_DIR}")
    
    # Check for specific Snort 3.8.1.0 headers to ensure compatibility
    if(EXISTS "${SNORT3_INCLUDE_DIR}/framework/snort_api.h")
        message(STATUS "Snort 3 API headers found - build should be compatible")
    else()
        message(WARNING "Snort 3 API headers missing - build may fail")
    endif()
    
    include_directories(${SNORT3_INCLUDE_DIR})
else()
    message(FATAL_ERROR "Snort 3 headers not found at ${SNORT3_INCLUDE_DIR}. Please install Snort 3.8.1.0 or set SNORT3_INCLUDE_DIR")
endif()

# Include project headers
include_directories(include)

# Collect source files
file(GLOB SOURCES "src/*.cpp")
list(REMOVE_ITEM SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/src/ddos_inspector.cpp")

# Core library for shared functionality
add_library(ddos_core STATIC ${SOURCES})
target_link_libraries(ddos_core Threads::Threads)

# Add TESTING definition to core library when building tests
if(BUILD_TESTING)
    target_compile_definitions(ddos_core PRIVATE TESTING)
endif()

# Main Snort 3 plugin
add_library(ddos_inspector SHARED src/ddos_inspector.cpp)
target_link_libraries(ddos_inspector ddos_core Threads::Threads)

# Plugin properties for Snort 3.8.1.0 compatibility
set_target_properties(ddos_inspector PROPERTIES
    OUTPUT_NAME "ddos_inspector"
    PREFIX "lib"
    SUFFIX ".so"
    CXX_VISIBILITY_PRESET default
    POSITION_INDEPENDENT_CODE ON
)

# Ensure plugin symbols are properly exported for Snort
target_compile_definitions(ddos_inspector PRIVATE SO_PUBLIC=)
target_compile_options(ddos_inspector PRIVATE -fvisibility=default)

# Install plugin to Snort directory
install(TARGETS ddos_inspector 
    LIBRARY DESTINATION /usr/local/lib/snort3_extra_plugins)

# Install configuration files
install(FILES snort_ddos_config.lua 
    DESTINATION /etc/snort/)

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

    # Main unit tests executable
    add_executable(unit_tests tests/unit_tests.cpp)
    target_link_libraries(unit_tests ddos_core gtest gtest_main Threads::Threads)
    target_compile_definitions(unit_tests PRIVATE TESTING)
    add_test(NAME AllTests COMMAND unit_tests)

    # Individual component test executables
    add_executable(test_stats_engine tests/test_stats_engine.cpp)
    target_link_libraries(test_stats_engine ddos_core gtest gtest_main Threads::Threads)
    target_compile_definitions(test_stats_engine PRIVATE TESTING)
    add_test(NAME StatsEngineTests COMMAND test_stats_engine)

    add_executable(test_behavior_tracker tests/test_behavior_tracker.cpp)
    target_link_libraries(test_behavior_tracker ddos_core gtest gtest_main Threads::Threads)
    target_compile_definitions(test_behavior_tracker PRIVATE TESTING)
    add_test(NAME BehaviorTrackerTests COMMAND test_behavior_tracker)

    add_executable(test_firewall_action tests/test_firewall_action.cpp)
    target_link_libraries(test_firewall_action ddos_core gtest gtest_main Threads::Threads)
    target_compile_definitions(test_firewall_action PRIVATE TESTING)
    add_test(NAME FirewallActionTests COMMAND test_firewall_action)

    # Realistic attack simulation tests
    if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_realistic_attacks.cpp")
        add_executable(test_realistic_attacks tests/test_realistic_attacks.cpp)
        target_link_libraries(test_realistic_attacks ddos_core gtest gtest_main Threads::Threads)
        target_compile_definitions(test_realistic_attacks PRIVATE TESTING)
        add_test(NAME RealisticAttackTests COMMAND test_realistic_attacks)
    endif()
endif()

# Package configuration
set(CPACK_PACKAGE_NAME "ddos-inspector")
set(CPACK_PACKAGE_VERSION "1.0.0")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Advanced DDoS Inspector Plugin for Snort 3.8.1.0")
set(CPACK_PACKAGE_VENDOR "DDoS Inspector Team")
set(CPACK_GENERATOR "DEB;RPM;TGZ")

include(CPack)

# Print build configuration summary
message(STATUS "")
message(STATUS "DDoS Inspector Build Configuration:")
message(STATUS "  Build Type: ${CMAKE_BUILD_TYPE}")
message(STATUS "  C++ Standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "  Snort 3 Include: ${SNORT3_INCLUDE_DIR}")
message(STATUS "  Testing: ${BUILD_TESTING}")
message(STATUS "  Install on: ${CMAKE_INSTALL_PREFIX}")
message(STATUS "")
