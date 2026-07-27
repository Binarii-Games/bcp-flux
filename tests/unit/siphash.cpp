// SipHash-2-4 correctness. The one test that matters for a hash is a
// known-answer test against the reference vectors from the SipHash paper
// (Aumasson & Bernstein): key = bytes 00..0f, message = the first `len` bytes
// of 00..0e. If our output matches the published values across message lengths
// 0..15, the algorithm is implemented correctly, including the partial-final-
// block tail handling.
#include <flux/util/siphash.h>

#include "harness.h"

#include <cstdint>

using bcp::flux::SipHash24;

// Reference SipHash-2-4 outputs for message lengths 0 through 15.
static const uint64_t REFERENCE[16] = {
    0x726fdb47dd0e0e31ull, 0x74f839c593dc67fdull, 0x0d6c8009d9a94f5aull, 0x85676696d7fb7e2dull,
    0xcf2794e0277187b7ull, 0x18765564cd99a68dull, 0xcbc9466e58fee3ceull, 0xab0200f58b01d137ull,
    0x93f5f5799a932462ull, 0x9e0082df0ba9e4b0ull, 0x7a5dbbc594ddb9f3ull, 0xf4b32f46226bada7ull,
    0x751e8fbc860ee5fbull, 0x14ea5627c0843d90ull, 0xf723ca908e7af2eeull, 0xa129ca6149be45e5ull,
};

// Every reference vector reproduces exactly.
static void matches_reference_vectors()
{
    uint8_t key[16];
    for (int i = 0; i < 16; ++i) key[i] = static_cast<uint8_t>(i);

    uint8_t message[16];
    for (int i = 0; i < 16; ++i) message[i] = static_cast<uint8_t>(i);

    for (uint32_t len = 0; len < 16; ++len)
        CHECK(SipHash24(key, message, len) == REFERENCE[len]);
}

// A one-bit change in the key changes the tag: the key actually keys the hash.
static void key_changes_the_tag()
{
    uint8_t message[8] = {1, 2, 3, 4, 5, 6, 7, 8};

    uint8_t key[16] = {0};
    uint64_t base = SipHash24(key, message, sizeof(message));

    key[0] ^= 0x01;
    CHECK(SipHash24(key, message, sizeof(message)) != base);
}

int main()
{
    matches_reference_vectors();
    key_changes_the_tag();
    return test::report();
}
