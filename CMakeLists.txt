cmake_minimum_required (VERSION 3.15)

project ("reset_remove")

set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:DebugDLL>")
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CXX_EXTENSIONS NO)

add_compile_options($<$<CXX_COMPILER_ID:MSVC>:/MP>)

add_subdirectory("third-party")

add_library(${PROJECT_NAME} SHARED "reset_remove.cpp")


set_target_properties(${PROJECT_NAME} PROPERTIES
  SUFFIX ".asi"
)

target_link_libraries(${PROJECT_NAME} PRIVATE kthook)