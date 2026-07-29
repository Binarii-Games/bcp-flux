// Byte cursor integrity. The wire format is little-endian by contract, so these
// assert the literal bytes the writer lays down (a round-trip alone would pass
// even if both ends agreed on the wrong order). They also cover the length
// field the writer maintains and the bounds checks that guard every call.
#include <common/wire/bytes_writer.h>
#include <common/wire/bytes_reader.h>

#include "harness.h"

#include <cstdint>

using bcp::common::BytesReader;
using bcp::common::BytesWriter;

// Multi-byte values land least-significant byte first, and the length field
// tracks how many bytes were written.
static void writes_little_endian_bytes()
{
    uint8_t  buffer[16] = {0};
    uint16_t length     = 0;
    BytesWriter writer{buffer, &length, sizeof(buffer)};

    CHECK(writer.PutU16(0x1234));
    CHECK(buffer[0] == 0x34 && buffer[1] == 0x12);

    CHECK(writer.PutU32(0x11223344));
    CHECK(buffer[2] == 0x44 && buffer[3] == 0x33 &&
          buffer[4] == 0x22 && buffer[5] == 0x11);

    CHECK(writer.PutU64(0x0102030405060708ull));
    CHECK(buffer[6]  == 0x08 && buffer[7]  == 0x07 &&
          buffer[8]  == 0x06 && buffer[9]  == 0x05 &&
          buffer[10] == 0x04 && buffer[11] == 0x03 &&
          buffer[12] == 0x02 && buffer[13] == 0x01);

    CHECK(length == 2 + 4 + 8);   // the writer summed every put
}

// A reader decodes the same little-endian bytes back to the original values.
static void reads_back_written_values()
{
    uint8_t  buffer[16] = {0};
    uint16_t length     = 0;
    BytesWriter writer{buffer, &length, sizeof(buffer)};
    CHECK(writer.PutU16(0xBEEF));
    CHECK(writer.PutU32(0xDEADC0DE));
    CHECK(writer.PutU64(0xA1B2C3D4E5F60718ull));

    BytesReader reader{buffer, length};
    uint16_t got16 = 0;
    uint32_t got32 = 0;
    uint64_t got64 = 0;
    CHECK(reader.TakeU16(got16) && got16 == 0xBEEF);
    CHECK(reader.TakeU32(got32) && got32 == 0xDEADC0DE);
    CHECK(reader.TakeU64(got64) && got64 == 0xA1B2C3D4E5F60718ull);
}

// A raw byte block round-trips unchanged through PutBytes / TakeBytes.
static void copies_raw_bytes_through()
{
    const uint8_t payload[5] = {0xDE, 0xAD, 0xBE, 0xEF, 0x42};

    uint8_t  buffer[8] = {0};
    uint16_t length    = 0;
    BytesWriter writer{buffer, &length, sizeof(buffer)};
    CHECK(writer.PutBytes(payload, sizeof(payload)));
    CHECK(length == sizeof(payload));

    uint8_t out[5] = {0};
    BytesReader reader{buffer, length};
    CHECK(reader.TakeBytes(out, sizeof(out)));
    for (int i = 0; i < 5; ++i)
        CHECK(out[i] == payload[i]);
}

// A write that would run past the buffer is refused and changes nothing.
static void refuses_write_past_capacity()
{
    uint8_t  buffer[3] = {0};
    uint16_t length    = 0;
    BytesWriter writer{buffer, &length, sizeof(buffer)};

    CHECK(!writer.PutU32(0xAABBCCDD));   // needs 4, only 3 free
    CHECK(length == 0);                  // refused write wrote nothing

    CHECK(writer.PutU16(0x1234));        // 2 of 3 fit
    CHECK(!writer.PutU16(0x5678));       // only 1 free now
    CHECK(writer.PutU8(0xFF));           // the last byte fits
    CHECK(length == 3);
}

// A read that would run past the end is refused.
static void refuses_read_past_end()
{
    const uint8_t data[3] = {1, 2, 3};
    BytesReader reader{data, sizeof(data)};

    uint32_t got32 = 0;
    CHECK(!reader.TakeU32(got32));        // needs 4, only 3 left

    uint16_t got16 = 0;
    uint8_t  got8  = 0;
    CHECK(reader.TakeU16(got16));         // 2 fit
    CHECK(reader.TakeU8(got8));           // 1 left
    CHECK(!reader.TakeU8(got8));          // exhausted
}

int main()
{
    writes_little_endian_bytes();
    reads_back_written_values();
    copies_raw_bytes_through();
    refuses_write_past_capacity();
    refuses_read_past_end();
    return test::report();
}
