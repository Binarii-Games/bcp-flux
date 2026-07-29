#pragma once

#include <cstdint>
#include <cstddef>

namespace bcp::common
{
    struct BytesWriter
    {
        uint8_t* p;
        uint16_t* l; ///< Points to the length field.
        size_t r; ///< Remaining free bytes.

        bool PutU8(uint8_t in);
        bool PutU16(uint16_t in);
        bool PutU32(uint32_t in);
        bool PutU64(uint64_t in);
        bool PutBytes(const uint8_t* data, size_t len);
        void IncrLenght(size_t len) noexcept;
    };
}