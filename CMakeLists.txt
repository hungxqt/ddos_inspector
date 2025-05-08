cmake_minimum_required(VERSION 3.10)
project(ddos_inspector)

set(CMAKE_CXX_STANDARD 17)

include_directories(include)

file(GLOB SOURCES "src/*.cpp")

add_executable(ddos_inspector ${SOURCES})

enable_testing()
add_subdirectory(tests)
