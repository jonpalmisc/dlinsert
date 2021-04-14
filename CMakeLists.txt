cmake_minimum_required(VERSION 3.0)

# Prohibit in-source builds
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_BINARY_DIR)
  message(FATAL_ERROR "In-source builds not allowed, please create a build directory.")
endif()

project(dlinsert)

add_executable(dlinsert src/dlinsert.c src/fileutils.c)
target_compile_features(dlinsert PRIVATE c_std_99)

install(TARGETS dlinsert DESTINATION bin)
