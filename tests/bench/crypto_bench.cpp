// The seal measured alone: AEAD encrypt/decrypt and the keyed MAC against
// nothing but memory — no sockets, no kernel. These are the numbers the
// send-path bench cannot isolate, because there the OS socket layer sits
// inside the measurement. Sizes bracket Flux traffic: a small control
// payload, a mid-size message, and a full wire packet.
#include <common/crypto/crypto.h>

#include "bench_harness.h"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <vector>

namespace crypto = bcp::common::crypto;

int main()
{
    crypto::SessionKey key;
    crypto::Nonce      nonce;
    if (!crypto::RandomBytes(key.data(), key.size()) ||
        !crypto::RandomBytes(nonce.data(), nonce.size()))
    {
        std::printf("  rng failed\n");
        return 0;
    }
    uint8_t associated = 0x5A;   // stands in for the controller byte

    std::printf("AEAD seal and keyed MAC, memory only (XChaCha20-Poly1305 / keyed blake2b)\n");

    constexpr uint64_t ITERATIONS = 1'000'000;

    for (size_t size : {size_t(64), size_t(256), size_t(1200)})
    {
        std::vector<uint8_t> plain(size, 0xAB);
        std::vector<uint8_t> cipher(size);
        std::vector<uint8_t> opened(size);
        crypto::Tag tag;

        std::printf("  --- %zu-byte payload ---\n", size);

        double encryptNs = bench::ns_per_op(ITERATIONS, 10000, [&]
        {
            crypto::Encrypt(cipher.data(), tag, key, nonce, plain.data(), size,
                            &associated, 1);
            bench::sink += tag[0];
        });
        bench::report("encrypt", encryptNs);
        std::printf("    %.2f GB/s\n", static_cast<double>(size) / encryptNs);

        // cipher and tag now hold a valid seal; every decrypt verifies it.
        double decryptNs = bench::ns_per_op(ITERATIONS, 10000, [&]
        {
            bool ok = crypto::Decrypt(opened.data(), key, nonce, cipher.data(), size,
                                      tag, &associated, 1);
            bench::sink += ok ? 1u : 0u;
        });
        bench::report("decrypt+verify", decryptNs);
        std::printf("    %.2f GB/s\n", static_cast<double>(size) / decryptNs);
    }

    // The handshake's confirmation MAC runs once per handshake, not per
    // packet; 128 bytes is its transcript scale.
    std::vector<uint8_t> transcript(128, 0xCD);
    crypto::Mac mac;
    double macNs = bench::ns_per_op(ITERATIONS, 10000, [&]
    {
        crypto::ComputeMac(mac, key, transcript.data(), transcript.size());
        bench::sink += mac[0];
    });
    bench::report("mac (128-byte transcript)", macNs);

    return 0;
}
