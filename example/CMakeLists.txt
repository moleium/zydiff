cmake_minimum_required(VERSION 3.20)
project(zydiff)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(${PROJECT_NAME}
  main.cpp
)

target_link_libraries(${PROJECT_NAME} PRIVATE
  zydiff
)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
