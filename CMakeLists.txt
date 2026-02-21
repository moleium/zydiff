cmake_minimum_required(VERSION 3.20)
project(zydiff)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(MSVC)
  add_compile_options(/MP)
endif()

if(NOT TARGET Zydis::Zydis)
    add_subdirectory(vendor/zydis)
endif()

add_subdirectory(example)

add_library(${PROJECT_NAME} STATIC
  src/core/decoder.cpp
  src/core/parser.cpp
  src/core/analyzer.cpp
  src/core/differ.cpp
  src/core/serializer.cpp
)

target_include_directories(${PROJECT_NAME} PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src
  ${CMAKE_CURRENT_SOURCE_DIR}/src/util
)

target_link_libraries(${PROJECT_NAME} PUBLIC
  Zydis::Zydis
)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
