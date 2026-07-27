#pragma once

#include <cstdint>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
#endif

#include <common/error.h>

namespace bcp::flux {

    class ChallengeGenerator {
    public:
        /** Time-bucket size. A challenge is valid for at least this long and at
            most 2x, depending on when in the bucket it was issued. 60s gives
            generous slop for clock differences and re-transmits; tighten for a
            smaller forge window.
         */
        static constexpr uint64_t WINDOW_SECONDS = 60;

        /** Generates a fresh random secret. Must be called before any Generate
            or Verify. Re-Init'ing rotates the secret and invalidates all
            outstanding challenges (correct behavior on node restart).
         */
        [[nodiscard]] common::Error Init();

        /** Issue a challenge for the given sender address, using the current
            time bucket. Caller embeds the returned value in the challenge
            packet.
         */
        uint64_t Generate(const sockaddr_storage& senderAddr) const;

        /** Verify a returned challenge against both the current and previous
            time bucket. Returns true if it matches what we would have issued.
         */
        bool Verify(const sockaddr_storage& senderAddr, uint64_t challenge) const;

    private:
        uint8_t secret_[16] = {};   ///< 128-bit SipHash key, set by Init().
        bool    initialized_ = false;

        /** Computes the canonical challenge for (addr, bucket). Both Generate
            and Verify go through here to keep issue and check symmetric.
         */
        uint64_t ComputeFor(const sockaddr_storage& addr, uint64_t bucket) const;

        /** Wall-clock bucket index from steady_clock. Verifier and issuer are
            the same node, so a shared monotonic clock is enough; no
            cross-machine sync needed.
         */
        static uint64_t CurrentBucket();
    };
}