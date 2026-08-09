// SipHash-2-4 correctness, as a known-answer test against the published
// reference vectors (Aumasson & Bernstein): key = bytes 00..0f, message = the
// first `len` bytes of 00..3f.
//
// All sixty four lengths, not the first sixteen. The compression loop runs
// len/8 times, so short messages drive it once or not at all and the whole
// table below 8 exercises only the tail. Sixteen vectors leave a truncated
// loop undetected: breaking it to compress the first block and skip the rest
// reproduces every vector up to length 15 and every token this codebase
// actually issues. Lengths past 16 are what pin the loop, and 28 is the one
// that matters most in practice because it is the challenge token length.
#include <flux/util/siphash.h>

#include "harness.h"

#include <cstdint>

using bcp::flux::SipHash24;

// Reference SipHash-2-4 outputs for message lengths 0 through 63.
static const uint64_t REFERENCE[64] = {
    0x726fdb47dd0e0e31ull, 0x74f839c593dc67fdull, 0x0d6c8009d9a94f5aull, 0x85676696d7fb7e2dull,
    0xcf2794e0277187b7ull, 0x18765564cd99a68dull, 0xcbc9466e58fee3ceull, 0xab0200f58b01d137ull,
    0x93f5f5799a932462ull, 0x9e0082df0ba9e4b0ull, 0x7a5dbbc594ddb9f3ull, 0xf4b32f46226bada7ull,
    0x751e8fbc860ee5fbull, 0x14ea5627c0843d90ull, 0xf723ca908e7af2eeull, 0xa129ca6149be45e5ull,
    0x3f2acc7f57c29bdbull, 0x699ae9f52cbe4794ull, 0x4bc1b3f0968dd39cull, 0xbb6dc91da77961bdull,
    0xbed65cf21aa2ee98ull, 0xd0f2cbb02e3b67c7ull, 0x93536795e3a33e88ull, 0xa80c038ccd5ccec8ull,
    0xb8ad50c6f649af94ull, 0xbce192de8a85b8eaull, 0x17d835b85bbb15f3ull, 0x2f2e6163076bcfadull,
    0xde4daaaca71dc9a5ull, 0xa6a2506687956571ull, 0xad87a3535c49ef28ull, 0x32d892fad841c342ull,
    0x7127512f72f27cceull, 0xa7f32346f95978e3ull, 0x12e0b01abb051238ull, 0x15e034d40fa197aeull,
    0x314dffbe0815a3b4ull, 0x027990f029623981ull, 0xcadcd4e59ef40c4dull, 0x9abfd8766a33735cull,
    0x0e3ea96b5304a7d0ull, 0xad0c42d6fc585992ull, 0x187306c89bc215a9ull, 0xd4a60abcf3792b95ull,
    0xf935451de4f21df2ull, 0xa9538f0419755787ull, 0xdb9acddff56ca510ull, 0xd06c98cd5c0975ebull,
    0xe612a3cb9ecba951ull, 0xc766e62cfcadaf96ull, 0xee64435a9752fe72ull, 0xa192d576b245165aull,
    0x0a8787bf8ecb74b2ull, 0x81b3e73d20b49b6full, 0x7fa8220ba3b2eceaull, 0x245731c13ca42499ull,
    0xb78dbfaf3a8d83bdull, 0xea1ad565322a1a0bull, 0x60e61c23a3795013ull, 0x6606d7e446282b93ull,
    0x6ca4ecb15c5f91e1ull, 0x9f626da15c9625f3ull, 0xe51b38608ef25f57ull, 0x958a324ceb064572ull,
};

// Every reference vector reproduces exactly.
static void matches_reference_vectors()
{
    uint8_t key[16];
    for (int i = 0; i < 16; ++i) key[i] = static_cast<uint8_t>(i);

    uint8_t message[64];
    for (int i = 0; i < 64; ++i) message[i] = static_cast<uint8_t>(i);

    for (uint32_t len = 0; len < 64; ++len)
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
