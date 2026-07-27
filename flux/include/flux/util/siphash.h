// --- bcp/util/siphash.h ---
// SipHash-2-4: a fast keyed pseudo-random function (Aumasson & Bernstein).
// Built for short keyed messages, our SYN-cookie / challenge-token case.
// 64-bit output. Same algorithm the Linux kernel uses for TCP SYN cookies and
// that many languages seed their default hasher with. Not a general MAC (use
// HMAC-SHA256), but right for the "issuer == verifier, secret never leaves the
// node" model: small, no deps, no length-extension, well-analyzed.

#pragma once

#include <cstddef>
#include <cstdint>

namespace bcp::flux {

    /** Hashes `len` bytes under a 16-byte key. Returns a 64-bit tag.

        For challenge generation, key = node secret, data = (addr || timeBucket).
    */
    inline uint64_t SipHash24(const uint8_t key[16], const uint8_t* data, size_t len) {
        auto rotl = [](uint64_t x, int b) -> uint64_t {
            return (x << b) | (x >> (64 - b));
        };

        auto load64 = [](const uint8_t* p) -> uint64_t {
            uint64_t v = 0;
            for (int i = 0; i < 8; i++) v |= static_cast<uint64_t>(p[i]) << (i * 8);
            return v;
        };

        uint64_t k0 = load64(key);
        uint64_t k1 = load64(key + 8);

        // Init constants from the SipHash spec.
        uint64_t v0 = 0x736f6d6570736575ULL ^ k0;
        uint64_t v1 = 0x646f72616e646f6dULL ^ k1;
        uint64_t v2 = 0x6c7967656e657261ULL ^ k0;
        uint64_t v3 = 0x7465646279746573ULL ^ k1;

        auto round = [&]() {
            v0 += v1; v1 = rotl(v1, 13); v1 ^= v0; v0 = rotl(v0, 32);
            v2 += v3; v3 = rotl(v3, 16); v3 ^= v2;
            v0 += v3; v3 = rotl(v3, 21); v3 ^= v0;
            v2 += v1; v1 = rotl(v1, 17); v1 ^= v2; v2 = rotl(v2, 32);
        };

        // Compression: 2 rounds per 8-byte block.
        const uint8_t* end = data + (len & ~static_cast<size_t>(7));
        while (data < end) {
            uint64_t m = load64(data);
            v3 ^= m;
            round();
            round();
            v0 ^= m;
            data += 8;
        }

        // Tail: pack remaining bytes plus the length-mod-256 marker into one block.
        uint64_t b = static_cast<uint64_t>(len) << 56;
        size_t left = len & 7;
        for (size_t i = 0; i < left; i++) {
            b |= static_cast<uint64_t>(data[i]) << (i * 8);
        }

        v3 ^= b;
        round();
        round();
        v0 ^= b;

        // Finalization: 4 rounds with v2 ^= 0xff.
        v2 ^= 0xff;
        round();
        round();
        round();
        round();

        return v0 ^ v1 ^ v2 ^ v3;
    }
}