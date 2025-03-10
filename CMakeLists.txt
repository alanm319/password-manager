cmake_minimum_required(VERSION 3.10)
project(PasswordManager CXX)

set(CMAKE_CXX_STANDARD 20)

find_package(PkgConfig REQUIRED)
pkg_check_modules(DEPS REQUIRED sqlcipher libsodium)

include_directories(include ${DEPS_INCLUDE_DIRS})

file(GLOB SRC_FILES src/*.cpp)

add_executable(password_manager ${SRC_FILES})

target_link_libraries(password_manager ${DEPS_LIBRARIES})
target_compile_options(password_manager PRIVATE ${DEPS_CFLAGS_OTHER})
