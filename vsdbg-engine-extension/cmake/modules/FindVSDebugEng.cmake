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

set(_find_vsdebugend_lib_path_suffix)
if(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86")
  set(_find_vsdebugend_lib_path_suffix "import-lib/x86")
elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "AMD64")
  set(_find_vsdebugend_lib_path_suffix "import-lib/x64")
elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "arm")
  set(_find_vsdebugend_lib_path_suffix "import-lib/arm")
elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "ARM64")
  set(_find_vsdebugend_lib_path_suffix "import-lib/arm64")
endif()

find_library(VSDebugEng_LIBRARY
  NAMES vsdebugeng
  PATH_SUFFIXES
    ${_find_vsdebugend_lib_path_suffix}
)
unset(_find_vsdebugend_lib_path_suffix)

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
