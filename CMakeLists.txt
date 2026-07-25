cmake_minimum_required(VERSION 3.16)

project(pqc_hybrid_vpn C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

find_package(PkgConfig REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)
pkg_check_modules(LIBOQS REQUIRED IMPORTED_TARGET liboqs)

add_compile_options(-Wall -Wextra -Wpedantic)
add_compile_definitions(_POSIX_C_SOURCE=200809L)

add_library(pqc_common
    src/common/aead.c
    src/common/framing.c
    src/common/hybrid_kdf.c
    src/common/secret_print.c
    src/common/timing.c
    src/common/state_machine.c
    src/common/tun.c
    src/common/telemetry.c
    src/common/ztna.c
    src/common/multipath.c
    src/common/ebpf_xdp.c
)

target_include_directories(pqc_common PUBLIC src/common)

add_executable(pqc_server src/server/server.c)
target_link_libraries(pqc_server PRIVATE pqc_common)

add_executable(pqc_client src/client/client.c)
target_link_libraries(pqc_client PRIVATE pqc_common)

add_executable(pqc_kem_server src/server/kem_server.c)
target_include_directories(pqc_kem_server PRIVATE ${LIBOQS_INCLUDE_DIRS} src/common)
target_link_directories(pqc_kem_server PRIVATE ${LIBOQS_LIBRARY_DIRS})
target_link_libraries(pqc_kem_server PRIVATE pqc_common oqs crypto)

add_executable(pqc_kem_client src/client/kem_client.c)
target_include_directories(pqc_kem_client PRIVATE ${LIBOQS_INCLUDE_DIRS} src/common)
target_link_directories(pqc_kem_client PRIVATE ${LIBOQS_LIBRARY_DIRS})
target_link_libraries(pqc_kem_client PRIVATE pqc_common oqs crypto)

add_executable(pqc_x25519_server src/server/x25519_server.c)
target_include_directories(pqc_x25519_server PRIVATE src/common)
target_link_libraries(pqc_x25519_server PRIVATE pqc_common crypto)

add_executable(pqc_x25519_client src/client/x25519_client.c)
target_include_directories(pqc_x25519_client PRIVATE src/common)
target_link_libraries(pqc_x25519_client PRIVATE pqc_common crypto)

add_executable(pqc_hybrid_seq_server src/server/hybrid_seq_server.c)
target_include_directories(pqc_hybrid_seq_server PRIVATE ${LIBOQS_INCLUDE_DIRS} src/common)
target_link_directories(pqc_hybrid_seq_server PRIVATE ${LIBOQS_LIBRARY_DIRS})
target_link_libraries(pqc_hybrid_seq_server PRIVATE pqc_common oqs crypto)

add_executable(pqc_hybrid_seq_client src/client/hybrid_seq_client.c)
target_include_directories(pqc_hybrid_seq_client PRIVATE ${LIBOQS_INCLUDE_DIRS} src/common)
target_link_directories(pqc_hybrid_seq_client PRIVATE ${LIBOQS_LIBRARY_DIRS})
target_link_libraries(pqc_hybrid_seq_client PRIVATE pqc_common oqs crypto)

add_executable(pqc_hybrid_par_server src/server/hybrid_par_server.c)
target_include_directories(pqc_hybrid_par_server PRIVATE ${LIBOQS_INCLUDE_DIRS} src/common)
target_link_directories(pqc_hybrid_par_server PRIVATE ${LIBOQS_LIBRARY_DIRS})
target_link_libraries(pqc_hybrid_par_server PRIVATE pqc_common oqs crypto Threads::Threads)

add_executable(pqc_hybrid_par_client src/client/hybrid_par_client.c)
target_include_directories(pqc_hybrid_par_client PRIVATE ${LIBOQS_INCLUDE_DIRS} src/common)
target_link_directories(pqc_hybrid_par_client PRIVATE ${LIBOQS_LIBRARY_DIRS})
target_link_libraries(pqc_hybrid_par_client PRIVATE pqc_common oqs crypto Threads::Threads)

add_executable(pqc_dsa_auth_server src/server/dsa_auth_server.c)
target_include_directories(pqc_dsa_auth_server PRIVATE ${LIBOQS_INCLUDE_DIRS} src/common)
target_link_directories(pqc_dsa_auth_server PRIVATE ${LIBOQS_LIBRARY_DIRS})
target_link_libraries(pqc_dsa_auth_server PRIVATE pqc_common oqs crypto)

add_executable(pqc_dsa_auth_client src/client/dsa_auth_client.c)
target_include_directories(pqc_dsa_auth_client PRIVATE ${LIBOQS_INCLUDE_DIRS} src/common)
target_link_directories(pqc_dsa_auth_client PRIVATE ${LIBOQS_LIBRARY_DIRS})
target_link_libraries(pqc_dsa_auth_client PRIVATE pqc_common oqs crypto)

add_executable(pqc_hybrid_auth_server src/server/hybrid_auth_server.c)
target_include_directories(pqc_hybrid_auth_server PRIVATE ${LIBOQS_INCLUDE_DIRS} src/common)
target_link_directories(pqc_hybrid_auth_server PRIVATE ${LIBOQS_LIBRARY_DIRS})
target_link_libraries(pqc_hybrid_auth_server PRIVATE pqc_common oqs crypto)

add_executable(pqc_hybrid_auth_client src/client/hybrid_auth_client.c)
target_include_directories(pqc_hybrid_auth_client PRIVATE ${LIBOQS_INCLUDE_DIRS} src/common)
target_link_directories(pqc_hybrid_auth_client PRIVATE ${LIBOQS_LIBRARY_DIRS})
target_link_libraries(pqc_hybrid_auth_client PRIVATE pqc_common oqs crypto)

add_executable(pqc_secure_server src/server/secure_server.c)
target_include_directories(pqc_secure_server PRIVATE ${LIBOQS_INCLUDE_DIRS} src/common)
target_link_directories(pqc_secure_server PRIVATE ${LIBOQS_LIBRARY_DIRS})
target_link_libraries(pqc_secure_server PRIVATE pqc_common oqs crypto)

add_executable(pqc_secure_client src/client/secure_client.c)
target_include_directories(pqc_secure_client PRIVATE ${LIBOQS_INCLUDE_DIRS} src/common)
target_link_directories(pqc_secure_client PRIVATE ${LIBOQS_LIBRARY_DIRS})
target_link_libraries(pqc_secure_client PRIVATE pqc_common oqs crypto)

add_executable(check_liboqs tests/kat/check_liboqs.c)
target_include_directories(check_liboqs PRIVATE ${LIBOQS_INCLUDE_DIRS})
target_link_directories(check_liboqs PRIVATE ${LIBOQS_LIBRARY_DIRS})
target_link_libraries(check_liboqs PRIVATE oqs crypto)

add_executable(test_ml_kem tests/kat/test_ml_kem.c)
target_include_directories(test_ml_kem PRIVATE ${LIBOQS_INCLUDE_DIRS} src/common)
target_link_directories(test_ml_kem PRIVATE ${LIBOQS_LIBRARY_DIRS})
target_link_libraries(test_ml_kem PRIVATE pqc_common oqs crypto)

add_executable(test_ml_dsa tests/kat/test_ml_dsa.c)
target_include_directories(test_ml_dsa PRIVATE ${LIBOQS_INCLUDE_DIRS} src/common)
target_link_directories(test_ml_dsa PRIVATE ${LIBOQS_LIBRARY_DIRS})
target_link_libraries(test_ml_dsa PRIVATE pqc_common oqs crypto)

add_executable(test_x25519 tests/kat/test_x25519.c)
target_include_directories(test_x25519 PRIVATE src/common)
target_link_libraries(test_x25519 PRIVATE pqc_common crypto)

add_executable(test_hybrid_kdf tests/kat/test_hybrid_kdf.c)
target_include_directories(test_hybrid_kdf PRIVATE ${LIBOQS_INCLUDE_DIRS} src/common)
target_link_directories(test_hybrid_kdf PRIVATE ${LIBOQS_LIBRARY_DIRS})
target_link_libraries(test_hybrid_kdf PRIVATE pqc_common oqs crypto)

add_executable(test_adaptive_buffer tests/kat/test_adaptive_buffer.c)
target_include_directories(test_adaptive_buffer PRIVATE src/common)
target_link_libraries(test_adaptive_buffer PRIVATE pqc_common)

add_executable(pqc_benchmark src/benchmarks/benchmark.c)
target_include_directories(pqc_benchmark PRIVATE ${LIBOQS_INCLUDE_DIRS} src/common)
target_link_directories(pqc_benchmark PRIVATE ${LIBOQS_LIBRARY_DIRS})
target_link_libraries(pqc_benchmark PRIVATE pqc_common oqs crypto)
