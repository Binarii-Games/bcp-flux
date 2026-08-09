#pragma once

#include <cstdint>
#include <cstddef>

namespace bcp::common
{
    /** A bounds-checked write cursor over a caller's buffer.

        `written` is where the running total goes. The cursor keeps it current
        so a caller never counts bytes itself, and it points at whatever the
        caller wants updated: a local for a one-shot encode, or a length field
        inside the buffer being built. */
    struct BytesWriter
    {
        uint8_t*  p;
        uint16_t* written;
        size_t    r;   ///< Remaining free bytes.

        bool PutU8(uint8_t in);
        bool PutU16(uint16_t in);
        bool PutU32(uint32_t in);
        bool PutU64(uint64_t in);
        bool PutBytes(const uint8_t* data, size_t len);
        void AddWritten(size_t len) noexcept;
    };
}