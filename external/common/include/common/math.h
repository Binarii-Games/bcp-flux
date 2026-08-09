#pragma once

#include <cstdint>

namespace bcp::common {
    inline uint32_t NextPowerOfTwo(uint32_t n) {
            if (n == 0) return 1;
            n--;
            n |= n >> 1;
            n |= n >> 2;
            n |= n >> 4;
            n |= n >> 8;
            n |= n >> 16;
            return n + 1;
    }

    /** Largest r where r*r*r <= n. Integer throughout, so it is exact and
        carries no floating point onto a path that must behave identically on
        every platform.

        Binary search rather than Newton: the range is small (the cube root of
        anything a uint64_t holds is under 2^22), it terminates in a fixed
        number of steps, and it needs no starting guess to be wrong about. */
    inline uint32_t CubeRoot(uint64_t n) {
            uint64_t low = 0, high = 1ull << 22;
            while (low < high) {
                    const uint64_t mid = low + (high - low + 1) / 2;
                    if (mid * mid * mid <= n) low = mid;
                    else                      high = mid - 1;
            }
            return static_cast<uint32_t>(low);
    }
}