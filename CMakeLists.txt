cmake_minimum_required(VERSION 3.10)
project(ddos_inspector)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Use the correct Snort 3 include directory
set(SNORT3_INCLUDE_DIR "/usr/local/snort3/include/snort")

if(EXISTS ${SNORT3_INCLUDE_DIR})
    message(STATUS "Found Snort 3 headers at: ${SNORT3_INCLUDE_DIR}")
    include_directories(${SNORT3_INCLUDE_DIR})
else()
    message(FATAL_ERROR "Snort 3 headers not found at ${SNORT3_INCLUDE_DIR}")
endif()

include_directories(include)

# Collect source files
file(GLOB SOURCES "src/*.cpp")

# Build as shared library for Snort 3 plugin
add_library(ddos_inspector SHARED ${SOURCES})

# Set plugin properties
set_target_properties(ddos_inspector PROPERTIES
    PREFIX ""
    SUFFIX ".so"
    CXX_VISIBILITY_PRESET hidden
)

# Link with required libraries
target_link_libraries(ddos_inspector pthread)

# Install to Snort plugin directory
install(TARGETS ddos_inspector 
    LIBRARY DESTINATION /usr/local/lib/snort3_extra_plugins)

# Google Test setup
include(FetchContent)
FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip
    DOWNLOAD_EXTRACT_TIMESTAMP true
)
# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

# Testing
enable_testing()

# Main unit tests executable
add_executable(unit_tests tests/unit_tests.cpp src/stats_engine.cpp src/behavior_tracker.cpp src/firewall_action.cpp)
target_compile_definitions(unit_tests PRIVATE TESTING)
target_link_libraries(unit_tests gtest gtest_main pthread)
add_test(NAME AllTests COMMAND unit_tests)

# Individual component test executables
add_executable(test_stats_engine tests/test_stats_engine.cpp src/stats_engine.cpp)
target_compile_definitions(test_stats_engine PRIVATE TESTING)
target_link_libraries(test_stats_engine gtest gtest_main pthread)
add_test(NAME StatsEngineTests COMMAND test_stats_engine)

add_executable(test_behavior_tracker tests/test_behavior_tracker.cpp src/behavior_tracker.cpp)
target_compile_definitions(test_behavior_tracker PRIVATE TESTING)
target_link_libraries(test_behavior_tracker gtest gtest_main pthread)
add_test(NAME BehaviorTrackerTests COMMAND test_behavior_tracker)

add_executable(test_firewall_action tests/test_firewall_action.cpp src/firewall_action.cpp)
target_compile_definitions(test_firewall_action PRIVATE TESTING)
target_link_libraries(test_firewall_action gtest gtest_main pthread)
add_test(NAME FirewallActionTests COMMAND test_firewall_action)
