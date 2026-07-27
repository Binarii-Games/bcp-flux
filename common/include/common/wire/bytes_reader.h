#pragma once

#include <cstdint>
#include <cstddef>

namespace bcp::common
{
    struct BytesReader
    {
        const uint8_t* p; ///< Data pointer
        size_t r; ///< Remaining bytes

        bool TakeU8(uint8_t& out);
        bool TakeU16(uint16_t& out);
        bool TakeU32(uint32_t& out);
        bool TakeU64(uint64_t& out);
        bool TakeBytes(uint8_t* dst, size_t len);
    };
}