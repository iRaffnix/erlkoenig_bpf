cmake_minimum_required(VERSION 3.14)
project(ubpf_port C)

# --- Find uBPF installation ---
set(UBPF_PREFIX "${CMAKE_SOURCE_DIR}/../third-party/lib"
    CACHE PATH "uBPF install prefix (contains include/ and lib/)")

if(NOT EXISTS "${UBPF_PREFIX}/include/ubpf.h")
    message(FATAL_ERROR
        "ubpf.h not found at ${UBPF_PREFIX}/include/ubpf.h\n"
        "Build uBPF first: see third-party/BUILD.md")
endif()

if(NOT EXISTS "${UBPF_PREFIX}/lib/libubpf.a")
    message(FATAL_ERROR
        "libubpf.a not found at ${UBPF_PREFIX}/lib/libubpf.a\n"
        "Build uBPF first: see third-party/BUILD.md")
endif()

# --- Target ---
add_executable(ubpf_port
    ubpf_port.c
    ubpf_maps.c
)

target_include_directories(ubpf_port PRIVATE
    "${UBPF_PREFIX}/include"
)

target_link_directories(ubpf_port PRIVATE
    "${UBPF_PREFIX}/lib"
)

target_link_libraries(ubpf_port PRIVATE
    ubpf
    m
    stdc++
)

# --- Compiler flags: hardened, kernel-quality ---
target_compile_options(ubpf_port PRIVATE
    -std=c11
    -O2
    -Wall -Wextra -Wpedantic
    -Wshadow -Wstrict-prototypes -Wmissing-prototypes
    -fPIE
    -fstack-protector-strong
    -D_FORTIFY_SOURCE=2
    -D_POSIX_C_SOURCE=199309L
)

target_link_options(ubpf_port PRIVATE
    -pie
    -Wl,-z,relro,-z,now
)

# --- Install to priv/ ---
set(PRIV_DIR "${CMAKE_SOURCE_DIR}/../priv")
install(TARGETS ubpf_port DESTINATION "${PRIV_DIR}")

# Convenience: also copy on build (so rebar3 eunit finds it)
add_custom_command(TARGET ubpf_port POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory "${PRIV_DIR}"
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:ubpf_port> "${PRIV_DIR}/"
    COMMENT "Copying ubpf_port to priv/"
)
