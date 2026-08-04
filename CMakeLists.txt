cmake_minimum_required(VERSION 3.25)
project(flux VERSION 0.2.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Emit compile_commands.json so editors and clang-tidy resolve includes the way
# the build does.
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# --------------------------------------------------------
# Warnings — surface everything the compiler can see statically.
# --------------------------------------------------------
if(MSVC)
    add_compile_options(/W4)
else()
    add_compile_options(-Wall -Wextra)
endif()

# Opt-in: fail the build on any warning. Off everywhere by default, including
# CI, so that a warning a new compiler version invents cannot break the build
# for everyone. Available for anyone who wants it locally: -DBCP_WERROR=ON.
option(BCP_WERROR "Treat warnings as errors" OFF)
if(BCP_WERROR)
    if(MSVC)
        add_compile_options(/WX)
    else()
        add_compile_options(-Werror)
    endif()
endif()

# --------------------------------------------------------
# Sanitizers — runtime bug detection the compiler cannot do statically.
# --------------------------------------------------------
# C++ compiles clean and still carries dangling references, off-by-ones into a
# buffer, reads of uninitialized members, or UB that only bites at a different
# -O level. Sanitizers turn those from "works until it doesn't" into a loud
# stack trace on the exact line. Enabled by default for non-release builds.
#
#   address    heap/stack overflow, use-after-free, double-free, leaks
#   undefined  signed overflow, null deref, misaligned load, bad enum, bad shift
#   thread     data races (mutually exclusive with address)
#
# Override:  -DBCP_SANITIZE=thread     (for the lock-free code)
#            -DBCP_SANITIZE=undefined  (UBSan only — see the note below)
#            -DBCP_SANITIZE=""         (disable)
#
# NOTE: some toolchains ship a broken ASan/TSan runtime that aborts in init
# (macOS Command Line Tools clang is the common one), so only `undefined` runs
# there. The full set runs on Linux/CI and on macOS with a real toolchain
# (Homebrew LLVM or full Xcode). This is a toolchain limitation, not a
# build-config one; the configure step below probes for it and falls back.
set(BCP_SANITIZE "address,undefined" CACHE STRING
    "Comma-separated sanitizers for non-release builds (address,undefined,thread). Empty to disable.")

# Never sanitize a release build — the instrumentation is a dev/test tool with
# a 2-3x cost, and must not ship.
if(BCP_SANITIZE AND NOT CMAKE_BUILD_TYPE MATCHES "^Rel")
    set(_bcp_effective "${BCP_SANITIZE}")
    string(REPLACE "," ";" _bcp_sanitizers "${_bcp_effective}")
    if(("thread" IN_LIST _bcp_sanitizers) AND ("address" IN_LIST _bcp_sanitizers))
        message(FATAL_ERROR "BCP_SANITIZE: 'thread' and 'address' cannot be combined; pick one.")
    endif()

    # Some toolchains ship a broken ASan runtime (Apple's Command Line Tools
    # clang aborts inside ASan's own init). Probe it at configure time and
    # fall back to UBSan-only rather than produce binaries that die at startup.
    if(("address" IN_LIST _bcp_sanitizers) AND NOT MSVC AND NOT CMAKE_CROSSCOMPILING)
        try_run(_bcp_asan_run _bcp_asan_ok
            SOURCE_FROM_CONTENT asan_probe.c "int main(void){return 0;}\n"
            CMAKE_FLAGS "-DCMAKE_C_FLAGS=-fsanitize=address"
            LINK_OPTIONS -fsanitize=address)
        if(NOT _bcp_asan_ok OR NOT _bcp_asan_run STREQUAL "0")
            message(WARNING
                "AddressSanitizer runtime is broken on this toolchain "
                "(probe binary failed to run) — falling back to UBSan only. "
                "Install a working toolchain (full Xcode or Homebrew LLVM) "
                "for ASan coverage; CI should provide it regardless.")
            set(_bcp_effective "undefined")
        endif()
    endif()

    if(MSVC)
        # MSVC only implements AddressSanitizer.
        string(REPLACE "," ";" _bcp_sanitizers "${_bcp_effective}")
        if("address" IN_LIST _bcp_sanitizers)
            add_compile_options(/fsanitize=address)
            message(STATUS "Sanitizers: address (MSVC)")
        endif()
    else()
        add_compile_options(-fsanitize=${_bcp_effective} -fno-omit-frame-pointer -g)
        add_link_options(-fsanitize=${_bcp_effective})
        message(STATUS "Sanitizers: ${_bcp_effective}")
    endif()
endif()

# --------------------------------------------------------
# Third-party: monocypher (vendored; BSD-2-Clause OR CC0-1.0)
# --------------------------------------------------------
add_library(monocypher STATIC external/monocypher/monocypher.c)
target_include_directories(monocypher PUBLIC external/monocypher)

# --------------------------------------------------------
# common - a standalone library, vendored in external/ the same way monocypher
# is. The copy here is a pinned snapshot that flux re-vendors when it wants a
# newer version, so a change to common does not reach flux until flux chooses
# to take it.
# --------------------------------------------------------
add_library(common STATIC)

file(GLOB_RECURSE COMMON_HEADERS CONFIGURE_DEPENDS "external/common/include/*.h")
file(GLOB_RECURSE COMMON_SOURCES CONFIGURE_DEPENDS "external/common/src/*.cpp")
target_sources(common PRIVATE ${COMMON_HEADERS} ${COMMON_SOURCES})

target_include_directories(common
    PUBLIC  external/common/include
    PRIVATE external/common/src
)

# crypto.h is a HEADER-ONLY wrapper (all functions inline) that calls monocypher
# + BCryptGenRandom directly in the header. Those symbols are therefore
# instantiated in EVERY consumer's TU, not inside common's .cpp, so the deps
# must be PUBLIC to propagate down the link graph.

# monocypher: crypto.h calls crypto_* inline -> consumers need it -> PUBLIC.
target_link_libraries(common PUBLIC monocypher)

# 16-byte CAS. PRIVATE if only used in common's .cpp; PUBLIC if used in
# common's public headers (inlined into consumers). x86-only flag — arm64
# has the capability without asking.
if(NOT MSVC AND CMAKE_SYSTEM_PROCESSOR MATCHES "(x86_64|AMD64|i686)")
    target_compile_options(common PRIVATE -mcx16)
endif()

# bcrypt: crypto.h calls BCryptGenRandom INLINE in a header, so the symbol is
# instantiated in every TU including crypto.h. PRIVATE would NOT propagate and
# those consumers would fail to link -> PUBLIC.
if(WIN32)
    target_link_libraries(common PUBLIC bcrypt)
endif()

# --------------------------------------------------------
# flux — the transport
# --------------------------------------------------------
add_library(flux STATIC)

file(GLOB_RECURSE FLUX_HEADERS CONFIGURE_DEPENDS "flux/include/*.h")
file(GLOB_RECURSE FLUX_SOURCES CONFIGURE_DEPENDS "flux/src/*.cpp")
target_sources(flux PRIVATE ${FLUX_HEADERS} ${FLUX_SOURCES})

target_include_directories(flux
    PUBLIC  flux/include
    PRIVATE flux/src
)

# common PUBLIC: flux public headers expose common types (Error, Result, crypto).
# This transitively carries monocypher + bcrypt (both PUBLIC on common) to flux
# and flux's consumers -> no need to relist them.
target_link_libraries(flux PUBLIC common)

# Windows sockets are flux-implementation-only -> PRIVATE.
if(WIN32)
    target_link_libraries(flux PRIVATE ws2_32 mswsock)
endif()

# --------------------------------------------------------
# Examples — small runnable programs written against the public API only, so
# they double as a check that the public surface is usable without reaching
# into internals. Built by default so they cannot rot; -DBCP_EXAMPLES=OFF to
# skip. One executable per .cpp, grouped by which library it demonstrates:
# examples/flux/, examples/common/. Drop a file in and it builds.
# --------------------------------------------------------
option(BCP_EXAMPLES "Build the examples" ON)
if(BCP_EXAMPLES)
    file(GLOB example_sources CONFIGURE_DEPENDS "examples/*/*.cpp")
    foreach(example_src ${example_sources})
        get_filename_component(example_name ${example_src} NAME_WE)
        add_executable(${example_name} ${example_src})
        target_link_libraries(${example_name} PRIVATE flux)
    endforeach()
endif()

# --------------------------------------------------------
# Tests — one plain executable per .cpp, registered with CTest and sanitized
# like everything else. Three categories, split by directory:
#
#   unit/         data-structure integrity          label: unit
#   integration/  full processes and edge cases      label: integration
#   acceptance/   properties a finished feature owes  label: acceptance
#   bench/        performance against a baseline      label: bench
#
# Fast CI runs unit + integration on every commit:
#   ctest -LE "bench|acceptance"
# The benches are heavier and run on demand or nightly:  ctest -L bench
#
# Acceptance tests state what a feature must do once it is finished, so they are
# written before the feature and fail until it lands. That is the point of them,
# and it is why they stay out of the per-commit gate: a red acceptance suite
# means the feature is not built yet, not that the tree is broken. Run them
# directly with  ctest -L acceptance  and fold them into the gate once the
# feature they describe is done.
#
# Each library owns its tests: flux's are in tests/, the vendored common's
# travel with it in external/common/tests/ and link common alone, which is what
# keeps the floor provably free of flux. Each tree carries the harness header
# its tests include, so common stays buildable outside this repo.
#
# Serial on purpose: the socket tests bind real UDP ports.
# --------------------------------------------------------
enable_testing()

function(register_tests glob label timeout link_target harness_dir)
    file(GLOB test_sources CONFIGURE_DEPENDS "${glob}")
    foreach(test_src ${test_sources})
        get_filename_component(test_name ${test_src} NAME_WE)
        add_executable(${test_name} ${test_src})
        target_link_libraries(${test_name} PRIVATE ${link_target})
        target_include_directories(${test_name} PRIVATE ${harness_dir})
        add_test(NAME ${test_name} COMMAND ${test_name})
        set_tests_properties(${test_name} PROPERTIES LABELS ${label} TIMEOUT ${timeout})
    endforeach()
endfunction()

register_tests("tests/unit/*.cpp"        unit        240 flux tests)
register_tests("tests/integration/*.cpp" integration 240 flux tests)
register_tests("tests/acceptance/*.cpp"  acceptance  240 flux tests)
register_tests("tests/bench/*.cpp"       bench       600 flux tests)

# The fault-injecting kernel sits beside the platform kernels in flux's private
# tree, so a test that drives one needs the same view of them the library has.

target_include_directories(flow_fault_recovery PRIVATE flux/src)
target_include_directories(mac_only_packet PRIVATE flux/src)
target_include_directories(flow_jam_eviction PRIVATE flux/src)
target_include_directories(concurrent_flows PRIVATE flux/src)
target_include_directories(grant_isolation PRIVATE flux/src)
target_include_directories(grant_reduction PRIVATE flux/src)
# Six phases of twenty threads, and a sanitized build runs it several times
# slower, so it gets more room than the ordinary integration budget.
set_tests_properties(concurrent_flows PROPERTIES TIMEOUT 600)

register_tests("external/common/tests/unit/*.cpp"  unit  240 common external/common/tests)
register_tests("external/common/tests/bench/*.cpp" bench 600 common external/common/tests)
