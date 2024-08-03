

add_executable(caller
  caller/main.cpp
)

target_compile_features(caller
  PRIVATE
    cxx_std_23
)

target_link_libraries(caller
  wtsapi32.lib
)

add_executable(callee
  callee/main.cpp
)

target_compile_features(callee
  PRIVATE
    cxx_std_23
)

install(
  TARGETS
    caller
    callee
  RUNTIME DESTINATION "bin/tests/${_arch_sub_dir}"
  COMPONENT tests
)
if(CHILDDEBUGGER_INSTALL_PDB)
  install(
    FILES
      "$<TARGET_PDB_FILE:caller>"
      "$<TARGET_PDB_FILE:callee>"
    DESTINATION "bin/tests/${_arch_sub_dir}"
    OPTIONAL
    COMPONENT tests
  )
endif()
