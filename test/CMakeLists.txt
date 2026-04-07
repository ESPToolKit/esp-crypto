add_executable(host_api_smoke host_api_smoke.cpp)
target_include_directories(host_api_smoke PRIVATE ${CMAKE_CURRENT_LIST_DIR}/../src)
target_compile_features(host_api_smoke PRIVATE cxx_std_17)
add_test(NAME host_api_smoke COMMAND host_api_smoke)
