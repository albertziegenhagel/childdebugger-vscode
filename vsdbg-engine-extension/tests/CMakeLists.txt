

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
