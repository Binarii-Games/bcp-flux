#include <common/wire/bytes_writer.h>

#include <cstring>

namespace bcp::common
{
    bool BytesWriter::PutU8(uint8_t in)
    {
        if (r < 1)
            return false;

        p[0] = in;
        
        ++p;
        --r;
        IncrLenght(1);
        
        return true;
    }

    bool BytesWriter::PutU16(uint16_t in)
    {
        if (r < 2)
            return false;

        p[0] = static_cast<uint8_t>(in >> 0);
        p[1] = static_cast<uint8_t>(in >> 8);
        
        p+=2;
        r-=2;
        IncrLenght(2);
        
        return true;
    }

    bool BytesWriter::PutU32(uint32_t in)
    {
        if (r < 4)
            return false;

        p[0] = static_cast<uint8_t>(in >> 0);
        p[1] = static_cast<uint8_t>(in >> 8);
        p[2] = static_cast<uint8_t>(in >> 16);
        p[3] = static_cast<uint8_t>(in >> 24);

        p+= 4;
        r-= 4;
        IncrLenght(4);

        return true;
    }

    bool BytesWriter::PutU64(uint64_t in)
    {
        if (r < 8)
            return false;

        p[0] = static_cast<uint8_t>(in >> 0);
        p[1] = static_cast<uint8_t>(in >> 8);
        p[2] = static_cast<uint8_t>(in >> 16);
        p[3] = static_cast<uint8_t>(in >> 24);
        p[4] = static_cast<uint8_t>(in >> 32);
        p[5] = static_cast<uint8_t>(in >> 40);
        p[6] = static_cast<uint8_t>(in >> 48);
        p[7] = static_cast<uint8_t>(in >> 56);
        
        p+=8;
        r-=8;
        IncrLenght(8);

        return true;
    }

    bool BytesWriter::PutBytes(const uint8_t* data, size_t len)
    {
        if (r < len)
            return false;

        std::memcpy(p, data, len);
        p+=len;
        r-=len;
        IncrLenght(len);

        return true;
    }

    void BytesWriter::IncrLenght(size_t len) noexcept
    {
        *l += static_cast<uint16_t>(len);
    }
}