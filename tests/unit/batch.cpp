// Packing messages into one packet's content.
//
// The contract: one message is stored bare so the packet stays identical on the
// wire to an unbatched one, and the length in front of it appears only when a
// second message forces it. Byte layouts are asserted literally, because a
// round trip through the same code would pass whether or not the bytes were
// ever laid out the way the wire expects.
#include <flux/wire/batch.h>

#include "harness.h"

#include <cstring>

namespace wire = bcp::flux::wire;

namespace
{
    constexpr uint16_t CAP = 64;

    wire::BatchCursor Fresh(uint8_t* buffer, uint16_t capacity = CAP)
    {
        std::memset(buffer, 0, capacity);
        return wire::BatchCursor{ buffer, 0, 0, 0, capacity };
    }
}

// One message is stored bare, with no length in front of it.
static void SingleMessageIsBare()
{
    uint8_t buffer[CAP];
    wire::BatchCursor cursor = Fresh(buffer);

    const uint8_t message[4] = { 0xAA, 0xBB, 0xCC, 0xDD };
    CHECK(wire::BatchAppend(cursor, message, sizeof(message)));

    CHECK(cursor.count == 1);
    CHECK(cursor.used == 4);            // the payload, nothing else
    CHECK(cursor.firstLen == 4);
    CHECK(buffer[0] == 0xAA);           // payload starts at byte zero
    CHECK(buffer[3] == 0xDD);
}

// The second message forces a length in front of the first, shifting it. The
// shift is over a region that overlaps itself, so every byte of the moved
// payload is checked rather than just its ends: a copy that reads a source byte
// after already overwriting it corrupts the middle and leaves the edges right.
static void SecondMessageInsertsTheFirstLength()
{
    constexpr uint16_t BIG = 40;
    uint8_t buffer[CAP];
    wire::BatchCursor cursor = Fresh(buffer);

    uint8_t first[BIG];
    for (uint16_t i = 0; i < BIG; ++i)
        first[i] = static_cast<uint8_t>(i * 7 + 1);   // distinct per position
    const uint8_t second[2] = { 0x11, 0x22 };

    CHECK(wire::BatchAppend(cursor, first, BIG));
    CHECK(wire::BatchAppend(cursor, second, sizeof(second)));

    CHECK(cursor.count == 2);
    // 2 (first's length) + 40 + 2 (second's length) + 2
    CHECK(cursor.used == 46);

    // First entry: length 40 little-endian, then the payload intact, all of it.
    CHECK(buffer[0] == 0x28);
    CHECK(buffer[1] == 0x00);
    CHECK(std::memcmp(buffer + 2, first, BIG) == 0);

    // Second entry: length 2 little-endian, then its payload.
    CHECK(buffer[42] == 0x02);
    CHECK(buffer[43] == 0x00);
    CHECK(buffer[44] == 0x11);
    CHECK(buffer[45] == 0x22);
}

// A third and beyond is an ordinary entry, no further shifting.
static void ThirdMessageAppendsPlainly()
{
    uint8_t buffer[CAP];
    wire::BatchCursor cursor = Fresh(buffer);

    const uint8_t one[1] = { 0x01 };
    CHECK(wire::BatchAppend(cursor, one, 1));
    CHECK(wire::BatchAppend(cursor, one, 1));
    const uint16_t afterTwo = cursor.used;
    CHECK(wire::BatchAppend(cursor, one, 1));

    CHECK(cursor.count == 3);
    CHECK(cursor.used == afterTwo + 3);   // one length plus one payload byte
}

// A refused append leaves the batch exactly as it was, never half written.
static void RefusedAppendLeavesBatchIntact()
{
    uint8_t buffer[CAP];
    wire::BatchCursor cursor = Fresh(buffer, 8);

    const uint8_t first[4] = { 0xAA, 0xBB, 0xCC, 0xDD };
    CHECK(wire::BatchAppend(cursor, first, sizeof(first)));
    const wire::BatchCursor before = cursor;

    const uint8_t big[8] = {};
    CHECK(!wire::BatchAppend(cursor, big, sizeof(big)));

    CHECK(cursor.used == before.used);
    CHECK(cursor.count == before.count);
    CHECK(cursor.firstLen == before.firstLen);
    CHECK(buffer[0] == 0xAA);   // untouched
}

// The second message must account for the prefix the first one grows, so a
// message that would fit without that hidden cost is still refused.
static void SecondMessageCountsTheRetroactivePrefix()
{
    uint8_t buffer[CAP];
    wire::BatchCursor cursor = Fresh(buffer, 10);

    const uint8_t first[6] = { 1, 2, 3, 4, 5, 6 };
    CHECK(wire::BatchAppend(cursor, first, sizeof(first)));   // used 6 of 10

    // Naively 2 (length) + 2 (payload) = 4 fits in the 4 remaining. It does
    // not, because the first message must also grow a 2-byte length.
    const uint8_t second[2] = { 7, 8 };
    CHECK(!wire::BatchFits(cursor, sizeof(second)));
    CHECK(!wire::BatchAppend(cursor, second, sizeof(second)));

    // One byte less does fit: 2 + 6 + 2 + 1 == 11 is still too big, so check
    // the boundary honestly against a larger capacity instead.
    wire::BatchCursor roomy = Fresh(buffer, 11);
    CHECK(wire::BatchAppend(roomy, first, sizeof(first)));
    const uint8_t tiny[1] = { 9 };
    CHECK(wire::BatchFits(roomy, sizeof(tiny)));
    CHECK(wire::BatchAppend(roomy, tiny, sizeof(tiny)));
    CHECK(roomy.used == 11);
}

// A validated chain walks back out as the same messages, in order.
static void ValidateAndWalkRoundTrip()
{
    uint8_t buffer[CAP];
    wire::BatchCursor cursor = Fresh(buffer);

    const uint8_t a[3] = { 1, 2, 3 };
    const uint8_t b[5] = { 4, 5, 6, 7, 8 };
    const uint8_t c[1] = { 9 };
    CHECK(wire::BatchAppend(cursor, a, sizeof(a)));
    CHECK(wire::BatchAppend(cursor, b, sizeof(b)));
    CHECK(wire::BatchAppend(cursor, c, sizeof(c)));

    CHECK(wire::BatchValidate(buffer, cursor.used));

    uint16_t offset = 0;
    const uint8_t* message = nullptr;
    uint16_t length = 0;

    CHECK(wire::BatchNext(buffer, cursor.used, offset, message, length));
    CHECK(length == 3 && std::memcmp(message, a, 3) == 0);
    CHECK(wire::BatchNext(buffer, cursor.used, offset, message, length));
    CHECK(length == 5 && std::memcmp(message, b, 5) == 0);
    CHECK(wire::BatchNext(buffer, cursor.used, offset, message, length));
    CHECK(length == 1 && std::memcmp(message, c, 1) == 0);

    CHECK(!wire::BatchNext(buffer, cursor.used, offset, message, length));   // exhausted
    CHECK(offset == cursor.used);
}

// Damaged framing is refused rather than partly trusted.
static void MalformedChainsAreRefused()
{
    uint8_t buffer[CAP];

    // A length claiming more than the content holds.
    buffer[0] = 0x10; buffer[1] = 0x00;   // says 16 bytes follow
    buffer[2] = 0xFF;
    CHECK(!wire::BatchValidate(buffer, 3));

    // A chain that stops short and leaves a tail.
    buffer[0] = 0x01; buffer[1] = 0x00; buffer[2] = 0xAA;   // one 1-byte entry
    buffer[3] = 0x99;                                        // stray trailing byte
    CHECK(!wire::BatchValidate(buffer, 4));

    // A truncated length field.
    buffer[0] = 0x02;
    CHECK(!wire::BatchValidate(buffer, 1));

    // A zero-length entry frames nothing and would never terminate progress.
    buffer[0] = 0x00; buffer[1] = 0x00;
    CHECK(!wire::BatchValidate(buffer, 2));

    // An exactly-consumed chain is the one that passes.
    buffer[0] = 0x01; buffer[1] = 0x00; buffer[2] = 0xAA;
    CHECK(wire::BatchValidate(buffer, 3));
}

int main()
{
    SingleMessageIsBare();
    SecondMessageInsertsTheFirstLength();
    ThirdMessageAppendsPlainly();
    RefusedAppendLeavesBatchIntact();
    SecondMessageCountsTheRetroactivePrefix();
    ValidateAndWalkRoundTrip();
    MalformedChainsAreRefused();
    return test::report();
}
