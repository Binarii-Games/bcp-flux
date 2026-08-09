// common/platform.h
#pragma once

#include <cstdint>

// immintrin.h is x86-only and hard-errors on arm64. Include it only where
// _mm_pause can exist. arm64's CpuPause uses inline asm, no header.
#if defined(_MSC_VER)
    #include <intrin.h>
#elif defined(__x86_64__) || defined(__i386__)
    #include <immintrin.h>
#endif


// MonotonicMicros needs a clock and nothing else here needs the OS. The socket
// headers this used to carry now live in flux, which is what wants them.
#ifdef _WIN32
    #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN
    #endif
    #include <windows.h>                 // QueryPerformanceCounter
#else
    #include <time.h>                    // clock_gettime
#endif

namespace bcp::common 
{
    #if defined(__aarch64__) || defined(_M_ARM64)
        static constexpr size_t CACHE_LINE = 128;
    #else
        static constexpr size_t CACHE_LINE = 64;
    #endif

    inline void CpuPause() {
        #if defined(__x86_64__) || defined(_M_X64)
            _mm_pause();
        #elif defined(__aarch64__) || defined(_M_ARM64)
            __asm__ volatile("yield" ::: "memory");
        #endif
    }

    /** Monotonic time in microseconds. Process-relative and never runs backwards;
        safe for timeouts and RTT measurement.

        @warning Meaningful only as a difference between two calls, never as wall time.
    */
    inline uint64_t MonotonicMicros() {
        #ifdef _WIN32
            static const int64_t freq = [] {
                LARGE_INTEGER f; QueryPerformanceFrequency(&f); return f.QuadPart;
            }();
            LARGE_INTEGER counter;
            QueryPerformanceCounter(&counter);
            // Split to avoid overflowing int64 on long uptimes: whole seconds
            // first, then the sub-second remainder scaled.
            const int64_t seconds   = counter.QuadPart / freq;
            const int64_t remainder = counter.QuadPart % freq;
            return static_cast<uint64_t>(seconds) * 1000000ull
                 + static_cast<uint64_t>(remainder * 1000000 / freq);
        #else
            timespec ts;
            clock_gettime(CLOCK_MONOTONIC, &ts);
            return static_cast<uint64_t>(ts.tv_sec) * 1000000ull
                 + static_cast<uint64_t>(ts.tv_nsec) / 1000ull;
        #endif
    }
}