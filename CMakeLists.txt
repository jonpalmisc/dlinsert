cmake_minimum_required(VERSION 3.0)

project(dlinsert)

add_executable(dlinsert dlinsert.c fileutils.c fileutils.h)
install(TARGETS dlinsert DESTINATION bin)
