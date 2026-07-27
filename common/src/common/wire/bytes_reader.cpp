#include <common/wire/bytes_reader.h>

#include <cstring>

namespace bcp::common
{
    bool BytesReader::TakeU8(uint8_t& out)
    {
        if (r < 1)
            return false;

        out = p[0];
        ++p;
        --r;

        return true;
    }

    bool BytesReader::TakeU16(uint16_t& out)
    {
        if (r < 2)
            return false;

        out = static_cast<uint16_t>(p[0])
            | static_cast<uint16_t>(p[1]) << 8;
        p += 2;
        r -= 2;

        return true;
    }

    bool BytesReader::TakeU32(uint32_t& out)
    {
        if (r < 4)
            return false;

        out = static_cast<uint32_t>(p[0])
            | static_cast<uint32_t>(p[1]) << 8
            | static_cast<uint32_t>(p[2]) << 16
            | static_cast<uint32_t>(p[3]) << 24;
        p += 4;
        r -= 4;

        return true;
    }

    bool BytesReader::TakeU64(uint64_t& out)
    {
        if (r < 8)
            return false;

        out = static_cast<uint64_t>(p[0])
            | static_cast<uint64_t>(p[1]) << 8
            | static_cast<uint64_t>(p[2]) << 16
            | static_cast<uint64_t>(p[3]) << 24
            | static_cast<uint64_t>(p[4]) << 32
            | static_cast<uint64_t>(p[5]) << 40
            | static_cast<uint64_t>(p[6]) << 48
            | static_cast<uint64_t>(p[7]) << 56;
        p += 8;
        r -= 8;

        return true;
    }

    bool BytesReader::TakeBytes(uint8_t* dst, size_t len)
    {
        if (r < len)
            return false;

        std::memcpy(dst, p, len);
        p += len;
        r -= len;

        return true;
    }
}