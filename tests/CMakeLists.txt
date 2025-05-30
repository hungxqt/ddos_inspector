cmake_minimum_required(VERSION 3.16)

# Tests are built by the main CMakeLists.txt using FetchContent
# This file is kept for potential future test organization

# All test executables are defined in the main CMakeLists.txt

# Add realistic attack test
add_executable(test_realistic_attacks test_realistic_attacks.cpp)
target_link_libraries(test_realistic_attacks 
    behavior_tracker
    stats_engine
    gtest 
    gtest_main
    pthread
)

# Add to test list
add_test(NAME RealisticAttackTests COMMAND test_realistic_attacks)