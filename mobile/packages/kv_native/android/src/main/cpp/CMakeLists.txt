cmake_minimum_required(VERSION 3.22.1)
project(kv_native)
add_library(kv_mobile_core SHARED IMPORTED)
# Rust cdylibs have no SONAME. Link by library name so DT_NEEDED stays device-portable.
set_target_properties(kv_mobile_core PROPERTIES
  IMPORTED_LOCATION "${CMAKE_CURRENT_SOURCE_DIR}/../../../../../../native/android/${ANDROID_ABI}/libkv_mobile_core.so"
  IMPORTED_NO_SONAME TRUE)
add_library(kv_native SHARED bridge.cpp)
target_link_libraries(kv_native kv_mobile_core)
target_compile_features(kv_native PRIVATE cxx_std_17)
target_compile_options(kv_native PRIVATE -Wall -Wextra -Werror)
