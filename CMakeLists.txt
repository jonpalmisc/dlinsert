cmake_minimum_required(VERSION 3.0)

project(dlinsert)

add_executable(dlinsert src/dlinsert.c src/fileutils.c)
install(TARGETS dlinsert DESTINATION bin)
