cmake_minimum_required(VERSION 3.0)

project(dlinsert)

add_executable(dlinsert src/dlinsert.c src/fileutils.c)
target_compile_features(dlinsert PRIVATE c_std_99)

install(TARGETS dlinsert DESTINATION bin)
