cmake_minimum_required (VERSION 3.25)

project(test-project)


set(CMAKE_CXX_STANDARD 20)


if(LINUX)
    set(TASK "Test task/SourceUnix.cpp" "Test task/std_testcase.h")
elseif(WIN32)
    set(TASK "Test task/Source.cpp" "Test task/std_testcase.h")
endif()

add_executable(test ${TASK})