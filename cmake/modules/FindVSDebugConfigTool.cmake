#[=======================================================================[.rst:
FindVSDebugEng
--------------

Finds the Visual Studio Debug Config tool.


#]=======================================================================]

find_program(VSDebugConfigTool_EXECUTABLE
    VsdConfigTool
)

mark_as_advanced(
  VSDebugConfigTool_EXECUTABLE
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(VSDebugConfigTool
  FOUND_VAR VSDebugConfigTool_FOUND
  REQUIRED_VARS
    VSDebugConfigTool_EXECUTABLE
)

if(VSDebugConfigTool_FOUND)
  function(configure_vs_debug_extension)
    cmake_parse_arguments(arg "" "TARGET;CONFIG;INCLUDE_DIR" "" ${ARGN})

    cmake_path(GET arg_CONFIG STEM LAST_ONLY CONFIG_BASE_NAME)

    file(MAKE_DIRECTORY "${arg_INCLUDE_DIR}")
    set(CONTRACT_HEADER "${arg_INCLUDE_DIR}/${CONFIG_BASE_NAME}.contract.h")

    add_custom_command(
      OUTPUT "${CONTRACT_HEADER}"
      COMMAND "${VSDebugConfigTool_EXECUTABLE}" "${arg_CONFIG}" "${CONTRACT_HEADER}"
      DEPENDS "${arg_CONFIG}"
    )

    target_sources(${arg_TARGET}
      PRIVATE
        "${CONTRACT_HEADER}"
    )
    target_include_directories(${arg_TARGET}
      PRIVATE
        "${arg_INCLUDE_DIR}"
    )

    get_property(TARGET_OUTPUT_LOCATION TARGET ${arg_TARGET} PROPERTY RUNTIME_OUTPUT_DIRECTORY)

    cmake_path(APPEND CONFIG_OUTPUT "${TARGET_OUTPUT_LOCATION}" "${CONFIG_BASE_NAME}.vsdconfig")
    
    add_custom_command(
      TARGET ${arg_TARGET}
      POST_BUILD
      COMMAND
        "${VSDebugConfigTool_EXECUTABLE}" "${arg_CONFIG}" "$<TARGET_FILE:${arg_TARGET}>" "${CONFIG_OUTPUT}"
      BYPRODUCTS
        "${CONFIG_OUTPUT}"
    )
  endfunction()
endif()
