project(zydiff)

# for c++17, handle format library
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(MSVC)
  add_compile_options(/MP)
endif()

add_subdirectory(vendor/zydis)

add_executable(${PROJECT_NAME}
  src/core/decoder.cpp
  src/core/parser.cpp
  src/core/analyzer.cpp
  src/core/differ.cpp

  # I don't care about making separate cmake for this
  example/main.cpp
  )

target_include_directories(${PROJECT_NAME} PRIVATE 
  ${CMAKE_CURRENT_SOURCE_DIR}/vendor
  ${CMAKE_CURRENT_SOURCE_DIR}/src
  ${CMAKE_CURRENT_SOURCE_DIR}/src/util
)

target_link_libraries(${PROJECT_NAME} PRIVATE
  Zydis
)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)