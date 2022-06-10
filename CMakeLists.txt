# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.10)

project(gOTzilla VERSION 3.2.0 LANGUAGES CXX)

# Executable will be in ../bin
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/./bin)
SET ( CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS} "-std=c++17 -O3 -m64 -lm -march=core-avx2 -msse2 -pthread")

add_executable(gotzilla gotzilla.cpp good_index.cpp share_at.cpp verifier_state.cpp ~/SealPIR/pir.cpp pir_server.cpp ~/SealPIR/pir_client.cpp)

# Import Microsoft SEAL
find_package(SEAL 3.2.0 EXACT REQUIRED)

# Link Microsoft SEAL
#target_link_libraries(sealexamples SEAL::seal)
target_link_libraries(gotzilla SEAL::seal ntl m gmp)

# Link additional external libraries
target_link_libraries(gotzilla gmp gmpxx cryptopp)
target_link_libraries(gotzilla ${CMAKE_CURRENT_SOURCE_DIR}/../SealPIR/libsealpir.a)
target_link_libraries(gotzilla  ~/MP-SPDZ/libSPDZ.so ~/MP-SPDZ/libFHE.so)
#include_directories( ${CMAKE_SOURCE_DIR} ~/MP-SPDZ ~/MP-SPDZ/local/lib ~/MP-SPDZ/mpir/ ~/SealPIR ~/SealPIR/bin /usr/local/include ~/cryptopp ~/SEAL/native/examples)
#include_directories( ${CMAKE_SOURCE_DIR} ~/MP-SPDZ ~/MP-SPDZ/local/lib ~/MP-SPDZ/mpir/ ~/SealPIR ~/SealPIR/bin /usr/local/include ~/cryptopp ~/SEAL/native/examples ~/MP-SPDZ/FHE)
include_directories( ${CMAKE_SOURCE_DIR} ~/MP-SPDZ ~/MP-SPDZ/local/lib ~/MP-SPDZ/mpir/ ~/SealPIR ~/SealPIR/bin /usr/local/include)


set(CMAKE_BUILD_TYPE DEBUG)
