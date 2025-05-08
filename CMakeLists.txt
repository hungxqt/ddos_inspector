cmake_minimum_required(VERSION 3.10)
project(ddos_inspector)

set(CMAKE_CXX_STANDARD 17)

include_directories(include)

file(GLOB SOURCES "src/*.cpp")

add_executable(ddos_inspector ${SOURCES})

enable_testing()
add_subdirectory(tests)

# Add to CMakeLists.txt
add_executable(unit_tests tests/unit_tests.cpp)
target_link_libraries(unit_tests gtest gtest_main pthread)
add_test(NAME AllTests COMMAND unit_tests)
