cmake_minimum_required(VERSION 3.10)

project(k3cvcfy)
add_executable(k3cvcfy k3cvcfy.c)

set(ARGPARSE_SHARED OFF)
add_subdirectory(argparse)
add_subdirectory(libk3cvc)

target_include_directories(k3cvcfy PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(k3cvcfy PRIVATE argparse k3cvc)
