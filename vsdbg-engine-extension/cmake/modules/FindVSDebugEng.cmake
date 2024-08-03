#[=======================================================================[.rst:
FindVSDebugEng
--------------

Finds the Visual Studio Debug Engine library.

Imported Targets
^^^^^^^^^^^^^^^^

This module provides the following imported targets, if found:

``VSDebugEng::VSDebugEng``
  The Visual Studio Debug Engine library

Result Variables
^^^^^^^^^^^^^^^^

This will define the following variables:

``VSDebugEng_FOUND``
  True if the system has the VSDebugEng library.
``VSDebugEng_INCLUDE_DIRS``
  Include directories needed to use VSDebugEng.
``VSDebugEng_LIBRARIES``
  Libraries needed to link to VSDebugEng.

Cache Variables
^^^^^^^^^^^^^^^

The following cache variables may also be set:

``VSDebugEng_INCLUDE_DIR``
  The directory containing ``VSDebugEng.h``.
``VSDebugEng_LIBRARY``
  The path to the VSDebugEng library.

#]=======================================================================]

find_path(VSDebugEng_INCLUDE_DIR
  NAMES
    VSDebugEng.h
  PATH_SUFFIXES
    inc
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

find_library(VSDebugEng_LIBRARY
  NAMES vsdebugeng
  PATH_SUFFIXES
    "import-lib/${_arch_sub_dir}"
)

mark_as_advanced(
  VSDebugEng_INCLUDE_DIR
  VSDebugEng_LIBRARY
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(VSDebugEng
  FOUND_VAR VSDebugEng_FOUND
  REQUIRED_VARS
    VSDebugEng_LIBRARY
    VSDebugEng_INCLUDE_DIR
)

if(VSDebugEng_FOUND)
  set(VSDebugEng_LIBRARIES ${VSDebugEng_LIBRARY})
  set(VSDebugEng_INCLUDE_DIRS ${VSDebugEng_INCLUDE_DIR})
  set(VSDebugEng_DEFINITIONS ${PC_VSDebugEng_CFLAGS_OTHER})
endif()

if(VSDebugEng_FOUND AND NOT TARGET VSDebugEng::VSDebugEng)
  add_library(VSDebugEng::VSDebugEng UNKNOWN IMPORTED)
  set_target_properties(VSDebugEng::VSDebugEng PROPERTIES
    IMPORTED_LOCATION "${VSDebugEng_LIBRARY}"
    INTERFACE_COMPILE_OPTIONS "${PC_VSDebugEng_CFLAGS_OTHER}"
    INTERFACE_INCLUDE_DIRECTORIES "${VSDebugEng_INCLUDE_DIR}"
  )
endif()
