# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.10)

project(SEALExamples VERSION 3.2.0 LANGUAGES CXX)

# Executable will be in ../bin
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/../bin)
SET ( CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS} "-std=c++11 -O3 -march=core-avx2 -msse" )

add_executable(sealexamples examples.cpp ~/MP-SPDZ/good_index.cpp share_at.cpp verifier_state.cpp pir.cpp pir_server.cpp pir_client.cpp)

# Import Microsoft SEAL
find_package(SEAL 3.2.0 EXACT REQUIRED)

# Link Microsoft SEAL
#target_link_libraries(sealexamples SEAL::seal)
target_link_libraries(sealexamples SEAL::seal ntl m gmp)

# Link additional external libraries
target_link_libraries(sealexamples gmp gmpxx cryptopp)
target_link_libraries(sealexamples ~/SealPIR/libsealpir.a)
target_link_libraries(sealexamples  ~/MP-SPDZ/libSPDZ.so ~/MP-SPDZ/libFHE.so)
include_directories( ${CMAKE_SOURCE_DIR} ~/MP-SPDZ ~/MP-SPDZ/local/lib ~/MP-SPDZ/mpir/ ~/SealPIR ~/SealPIR/bin /usr/local/include ~/cryptopp)

set(CMAKE_BUILD_TYPE DEBUG)
