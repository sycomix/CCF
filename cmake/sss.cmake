# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set(SSS_PREFIX
    ${CCF_DIR}/3rdparty/sss
    CACHE PATH "Prefix to the Shamir Secret Sharing library"
)
message(STATUS "Using SSS at ${SSS_PREFIX}")

set(SSS_SRC
    ${SSS_PREFIX}/sss.c ${SSS_PREFIX}/hazmat.c
    ${SSS_PREFIX}/tweetnacl.c
)

# TODO: Which compile flags to use here? https://github.com/dsprenkels/sss/blob/master/Makefile#L1-L4
# unroll loop too?

if("sgx" IN_LIST TARGET)
  add_library(sss.enclave STATIC ${SSS_SRC})
  set_property(TARGET sss.enclave PROPERTY POSITION_INDEPENDENT_CODE ON)
  use_oe_mbedtls(sss.enclave)
  target_include_directories(
    sss.enclave PRIVATE openenclave::oelibc
  )
  target_include_directories(
    sss.enclave
    PUBLIC
    $<BUILD_INTERFACE:${CCF_DIR}/src/tls>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_PREFIX}/include/ccf/tls>
  )
  install(TARGETS sss.enclave EXPORT ccf DESTINATION lib)
endif()

add_library(sss.host STATIC ${SSS_SRC})
set_property(TARGET sss.host PROPERTY POSITION_INDEPENDENT_CODE ON)
target_include_directories(
  sss.host
  PUBLIC
  $<BUILD_INTERFACE:${CCF_DIR}/src/tls>
  $<INSTALL_INTERFACE:${CMAKE_INSTALL_PREFIX}/include/ccf/tls>
)
# use_client_mbedtls(sss.host)
install(TARGETS sss.host EXPORT ccf DESTINATION lib)