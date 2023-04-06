cmake_minimum_required(VERSION 3.25)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/modules")

project(ChildDebuggerExtension VERSION 0.1 LANGUAGES CXX)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "bin")

find_package(VSDebugEng REQUIRED)
find_package(VSDebugConfigTool REQUIRED)

add_library(ChildDebugger SHARED)

target_compile_features(ChildDebugger
  PRIVATE
    cxx_std_23
)

target_compile_definitions(ChildDebugger
  PRIVATE
    "_USRDLL"
    # "_AMD64_"
)

target_sources(ChildDebugger
  PRIVATE
    "src/ChildDebugger.def"
    "src/dllmain.cpp"
    "src/ntsuspend.cpp"
    "src/ChildDebuggerService.cpp"
)

target_link_libraries(ChildDebugger
  PRIVATE
    VSDebugEng::VSDebugEng
)

configure_vs_debug_extension(
  TARGET ChildDebugger
  CONFIG
    "${CMAKE_CURRENT_SOURCE_DIR}/src/ChildDebugger.vsdconfigxml"
  INCLUDE_DIR
    "${CMAKE_CURRENT_BINARY_DIR}/include"
)

add_subdirectory(tests)
