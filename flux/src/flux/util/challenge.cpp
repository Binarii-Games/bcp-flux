// --- challenge.cpp ---

// #include <flux/handshake/challenge.h>
#include <flux/util/challenge.h>
#include <flux/util/siphash.h>

#include <common/crypto/crypto.h>

#include <chrono>
#include <cstring>

namespace bcp::flux {

    common::Error ChallengeGenerator::Init() {
        // Straight from the platform CSPRNG, so all 16 bytes are independent.
        // Drawing them from a seeded generator instead would cap the key at
        // the entropy of its seed however wide the key is.
        if (!common::crypto::RandomBytes(secret_, sizeof(secret_)))
            return common::Error::RandomFailed;

        initialized_ = true;
        return common::Error::Ok;
    }

    uint64_t ChallengeGenerator::Generate(const sockaddr_storage& senderAddr) const {
        return ComputeFor(senderAddr, CurrentBucket());
    }

    bool ChallengeGenerator::Verify(const sockaddr_storage& senderAddr, uint64_t challenge) const {
        // Check current and previous bucket: an issue late in one bucket may
        // be verified early in the next, and without the second check valid
        // handshakes near boundaries would fail.
        uint64_t bucket = CurrentBucket();
        if (challenge == ComputeFor(senderAddr, bucket))      return true;
        if (bucket > 0 &&
            challenge == ComputeFor(senderAddr, bucket - 1))  return true;
        return false;
    }

    uint64_t ChallengeGenerator::ComputeFor(const sockaddr_storage& addr, uint64_t bucket) const {
        // Addresses are dual-stack IPv6: the OS hands us AF_INET6 with IPv4 in
        // the ::ffff:a.b.c.d mapped form. Issue and verify see the same bytes,
        // so we hash them as-is.
        //
        // Layout: family(2) || port(2) || in6_addr(16) || bucket(8) = 28 bytes.
        // family/port stay in native (network-order) form from sockaddr_in6; no
        // byte-swap, since the comparison is byte-for-byte against ourselves.
        uint8_t input[28];
        const auto* a6 = reinterpret_cast<const sockaddr_in6*>(&addr);

        const uint16_t family = a6->sin6_family;
        const uint16_t port   = a6->sin6_port;

        std::memcpy(input +  0, &family,         2);
        std::memcpy(input +  2, &port,           2);
        std::memcpy(input +  4, &a6->sin6_addr, 16);
        std::memcpy(input + 20, &bucket,         8);

        return SipHash24(secret_, input, sizeof(input));
    }

    uint64_t ChallengeGenerator::CurrentBucket() {
        // steady_clock is monotonic, so no NTP jumps, and issuer and verifier
        // share the process, so no cross-clock alignment. On restart the secret
        // changes anyway, invalidating any outstanding challenges.
        const auto now  = std::chrono::steady_clock::now().time_since_epoch();
        const auto secs = std::chrono::duration_cast<std::chrono::seconds>(now).count();
        return static_cast<uint64_t>(secs) / WINDOW_SECONDS;
    }
}