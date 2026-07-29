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
}