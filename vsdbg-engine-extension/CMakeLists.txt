cmake_minimum_required(VERSION 3.25)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/modules")

project(ChildDebuggerExtension VERSION 0.1 LANGUAGES CXX)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "bin")

option(CHILDDEBUGGER_INSTALL_PDB "Install PDB files with the DLLs" OFF)

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
    "VSDEBUGENG_USE_CPP11_SCOPED_ENUMS"
)

target_sources(ChildDebugger
  PRIVATE
    "src/ChildDebugger.def"
    "src/dllmain.cpp"
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

set(_arch_sub_dir)
if(MSVC)
  if("${CMAKE_CXX_COMPILER_ARCHITECTURE_ID}" STREQUAL "X86")
    set(_arch_sub_dir "x86")
  elseif("${CMAKE_CXX_COMPILER_ARCHITECTURE_ID}" STREQUAL "x64")
    set(_arch_sub_dir "x64")
  elseif("${CMAKE_CXX_COMPILER_ARCHITECTURE_ID}" STREQUAL "ARMV7")
    set(_arch_sub_dir "arm")
  elseif("${CMAKE_CXX_COMPILER_ARCHITECTURE_ID}" STREQUAL "ARM64")
    set(_arch_sub_dir "arm64")
  endif()
else()
  if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86|AMD64")
    if("${CMAKE_SIZEOF_VOID_P}" EQUAL "4")
      set(_arch_sub_dir "x86")
    else()
      set(_arch_sub_dir "x64")
    endif()
  elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "arm|ARM64")
    if("${CMAKE_SIZEOF_VOID_P}" EQUAL "4")
      set(_arch_sub_dir "arm")
    else()
      set(_arch_sub_dir "arm64")
    endif()
  endif()
endif()

install(
  TARGETS
    ChildDebugger
  RUNTIME DESTINATION "bin/${_arch_sub_dir}"
)
if(CHILDDEBUGGER_INSTALL_PDB)
  install(
    FILES
      "$<TARGET_PDB_FILE:ChildDebugger>"
    DESTINATION "bin/${_arch_sub_dir}"
    OPTIONAL
  )
endif()

install(
  FILES
    "${CMAKE_CURRENT_BINARY_DIR}/bin/ChildDebugger.vsdconfig"
  DESTINATION bin
)

add_subdirectory(tests)
