#[=======================================================================[.rst:
FindNETFXSDK
--------------

Finds the .NET Framework SDK unmanaged API headers (NETFXSDK).

Imported Targets
^^^^^^^^^^^^^^^^

This module provides the following imported targets, if found:

``NETFXSDK::NETFXSDK``
  The .NET Framework SDK unmanaged API

Result Variables
^^^^^^^^^^^^^^^^

This will define the following variables:

``NETFXSDK_FOUND``
  True if the system has the .NET Framework SDK.
``NETFXSDK_INCLUDE_DIRS``
  Include directories needed to use .NET Framework SDK.

Cache Variables
^^^^^^^^^^^^^^^

The following cache variables may also be set:

``NETFXSDK_INCLUDE_DIR``
  The directory containing ``cor.h``.

#]=======================================================================]

find_path(NETFXSDK_INCLUDE_DIR
  NAMES
    cor.h
)

mark_as_advanced(
  NETFXSDK_INCLUDE_DIR
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(NETFXSDK
  FOUND_VAR NETFXSDK_FOUND
  REQUIRED_VARS
    NETFXSDK_INCLUDE_DIR
)

if(NETFXSDK_FOUND)
  set(NETFXSDK_INCLUDE_DIRS ${NETFXSDK_INCLUDE_DIR})
endif()

if(NETFXSDK_FOUND AND NOT TARGET NETFXSDK::NETFXSDK)
  add_library(NETFXSDK INTERFACE)
  set_target_properties(NETFXSDK PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES "${NETFXSDK_INCLUDE_DIR}"
  )
  add_library(NETFXSDK::NETFXSDK ALIAS NETFXSDK)
endif()
