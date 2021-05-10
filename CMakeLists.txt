cmake_minimum_required (VERSION 3.5)

project (libraop)

find_package(OpenSSL REQUIRED)

include_directories(${CMAKE_SOURCE_DIR}/vendor/alac/codec)
include_directories(${CMAKE_SOURCE_DIR}/vendor/curve25519/source)
include_directories(${CMAKE_SOURCE_DIR}/vendor/curve25519/include)
include_directories(${CMAKE_SOURCE_DIR}/vendor/valgrind/include)
include_directories(${CMAKE_SOURCE_DIR}/vendor/valgrind/memcheck)
include_directories(${CMAKE_SOURCE_DIR}/vendor/libplist/src)
include_directories(${CMAKE_SOURCE_DIR}/vendor/libplist/include)
include_directories(${CMAKE_SOURCE_DIR}/vendor/libplist/libcnary/include)

include_directories(${CMAKE_SOURCE_DIR}/src)
include_directories(${CMAKE_SOURCE_DIR}/src/inc)
include_directories(${CMAKE_SOURCE_DIR}/tools)

set(PROGSRC
    tools/log_util.c
    src/raop_client.c
    src/rtsp_client.c
    src/aes.c src/aexcl_lib.c
    src/base64.c
    src/alac_wrapper.cpp
    src/aes_ctr.c
    src/srp.c
)

set(CURVESRC
    ${CMAKE_SOURCE_DIR}/vendor/curve25519/source/curve25519_dh.c
    ${CMAKE_SOURCE_DIR}/vendor/curve25519/source/curve25519_mehdi.c
    ${CMAKE_SOURCE_DIR}/vendor/curve25519/source/curve25519_order.c
    ${CMAKE_SOURCE_DIR}/vendor/curve25519/source/curve25519_utils.c
    ${CMAKE_SOURCE_DIR}/vendor/curve25519/source/custom_blind.c
    ${CMAKE_SOURCE_DIR}/vendor/curve25519/source/ed25519_sign.c
    ${CMAKE_SOURCE_DIR}/vendor/curve25519/source/ed25519_verify.c
)

set(ALACSRC
    ${CMAKE_SOURCE_DIR}/vendor/alac/codec/ag_dec.c
    ${CMAKE_SOURCE_DIR}/vendor/alac/codec/ag_enc.c
    ${CMAKE_SOURCE_DIR}/vendor/alac/codec/ALACBitUtilities.c
    ${CMAKE_SOURCE_DIR}/vendor/alac/codec/ALACDecoder.cpp
    ${CMAKE_SOURCE_DIR}/vendor/alac/codec/ALACEncoder.cpp
    ${CMAKE_SOURCE_DIR}/vendor/alac/codec/dp_dec.c
    ${CMAKE_SOURCE_DIR}/vendor/alac/codec/dp_enc.c
    ${CMAKE_SOURCE_DIR}/vendor/alac/codec/EndianPortable.c
    ${CMAKE_SOURCE_DIR}/vendor/alac/codec/matrix_dec.c
    ${CMAKE_SOURCE_DIR}/vendor/alac/codec/matrix_enc.c
)

set(PLISTSRC
    ${CMAKE_SOURCE_DIR}/vendor/libplist/src/bplist.c
    ${CMAKE_SOURCE_DIR}/vendor/libplist/src/time64.c
    ${CMAKE_SOURCE_DIR}/vendor/libplist/src/xplist.c
    ${CMAKE_SOURCE_DIR}/vendor/libplist/src/plist.c
    ${CMAKE_SOURCE_DIR}/vendor/libplist/src/bytearray.c
    ${CMAKE_SOURCE_DIR}/vendor/libplist/src/ptrarray.c
    ${CMAKE_SOURCE_DIR}/vendor/libplist/src/hashtable.c
    ${CMAKE_SOURCE_DIR}/vendor/libplist/src/base64.c
    ${CMAKE_SOURCE_DIR}/vendor/libplist/libcnary/cnary.c
    ${CMAKE_SOURCE_DIR}/vendor/libplist/libcnary/node_list.c
    ${CMAKE_SOURCE_DIR}/vendor/libplist/libcnary/node.c
)


add_subdirectory(${CMAKE_SOURCE_DIR}/vendor/pybind11)
pybind11_add_module(${PROJECT_NAME} python/bindings.cpp ${PROGSRC} ${CURVESRC} ${ALACSRC} ${PLISTSRC})

target_compile_definitions(${PROJECT_NAME} PRIVATE VERSION_INFO=${LIBRAOP_VERSION_INFO})
target_link_libraries(${PROJECT_NAME} PRIVATE OpenSSL::Crypto)
