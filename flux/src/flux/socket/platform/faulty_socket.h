#pragma once

#include <flux/platform.h>

#include <cstdint>
#include <mutex>

#include <flux/internal/constants.h>

#ifdef _WIN32
#include <flux/socket/platform/win_socket.h>
#else
#include <flux/socket/platform/posix_socket.h>
#endif

namespace bcp::flux::platform
{
#ifdef _WIN32
    using FaultyBase = WinSocket;
#else
    using FaultyBase = PosixSocket;
#endif

    /** A real socket that damages its own traffic on purpose.

        Everything a packet goes through is the ordinary platform path, so what
        is being tested is the transport and not a simulation of one. Only the
        decision to deliver a packet, delay it, repeat it or spoil it is
        synthetic. Loopback never loses anything, which leaves retransmission,
        reordering and handshake recovery untested by every ordinary run.

        Two ways to drive it, and they compose. A Profile sets rates and a seed,
        which is reproducible: the same seed damages the same packets in the same
        order, so a failure replays exactly. The scripted calls name individual
        packets instead, for when a specific interleaving is the point rather
        than a rate. Scripted faults are consumed first and the profile applies
        to whatever they do not claim.

        Faults land on the send side by default, which covers loss, delay and
        reordering. Receive-side faults model the asymmetric case, where a peer
        hears everything and is heard by nothing, which is what breaks a
        handshake rather than merely slowing it.

        Thread-safe by a single lock over the whole operation, because a test
        that drives one socket from several threads is exactly the test worth
        writing and the alternative is faults and concurrency never appearing
        together. The lock is coarse on purpose: this is a test tool, the
        underlying socket is non-blocking so nothing waits under it, and being
        obviously correct is worth more here than being quick. */
    class FaultySocket : public FaultyBase
    {
    public:
        enum class Direction : uint8_t { Send, Receive, Both };

        struct Profile
        {
            /** Same seed, same damage, same order. Zero takes a fixed default
                rather than a clock, so a run with no seed still replays. */
            uint64_t  seed = 0;
            Direction applyTo = Direction::Send;

            /** Percent chance per packet. Independent unless burstLoss says
                otherwise. */
            uint8_t lossPercent      = 0;
            uint8_t duplicatePercent = 0;   ///< deliver twice, exercising dedupe
            uint8_t reorderPercent   = 0;   ///< hold and release behind later packets
            uint8_t corruptPercent   = 0;   ///< flip one bit, so the AEAD must reject it

            /** Extra loss applied only to handshake packets, which are the
                cleartext internal ones an on-path observer can pick out by the
                controller byte. A handshake is the one exchange no retransmit
                covers, so its loss is worth aiming at directly. */
            uint8_t handshakeLossPercent = 0;

            /** Consecutive packets discarded once loss fires. Real paths lose in
                bursts, and a burst defeats recovery that independent loss does
                not. */
            uint16_t burstLoss = 1;

            /** Held before delivery. Jitter is added on top, uniform in
                [0, jitterMicros), which is what makes arrival order vary. */
            uint32_t latencyMicros = 0;
            uint32_t jitterMicros  = 0;

            /** How many later packets a reordered one is released behind. */
            uint16_t reorderDepth = 2;
        };

        struct Stats
        {
            uint64_t sent        = 0;
            uint64_t received    = 0;
            uint64_t dropped     = 0;
            uint64_t duplicated  = 0;
            uint64_t corrupted   = 0;
            uint64_t delayed     = 0;
            uint64_t reordered   = 0;
            uint64_t handshakesDropped = 0;
        };

        /** The faulty socket bound to this port, or null. Socket owns its
            kernel privately, so this is how a test reaches the one it just
            created without widening the socket's own surface for a tool that
            only exists for tests. */
        [[nodiscard]] static FaultySocket* ForPort(uint16_t port) noexcept;

        void SetProfile(const Profile& profile) noexcept;
        [[nodiscard]] Profile GetProfile() const noexcept
        { std::lock_guard<std::recursive_mutex> guard(mutex_); return profile_; }

        // --- Scripted faults. Exact, consumed once, checked before the rates. ---

        /** Discards the next `count` packets outright. */
        void DropNext(uint32_t count) noexcept;
        /** Discards the packet at this ordinal, counted from the first packet
            this socket ever handled. Lets a test name the third handshake
            packet, or the packet that opens a flow. */
        void DropAt(uint64_t ordinal) noexcept;
        /** Flips a bit in the next `count` packets. They must fail the seal. */
        void CorruptNext(uint32_t count) noexcept;
        /** Holds the next `count` packets for `micros` before delivering. */
        void DelayNext(uint32_t count, uint32_t micros) noexcept;
        /** Discards every handshake packet while set, so a test can hold a peer
            unestablished for as long as it likes and then let it through. */
        void BlockHandshakes(bool blocked) noexcept;

        [[nodiscard]] Stats GetStats() const noexcept
        { std::lock_guard<std::recursive_mutex> guard(mutex_); return stats_; }
        void ResetStats() noexcept
        { std::lock_guard<std::recursive_mutex> guard(mutex_); stats_ = Stats{}; }

        /** How many packets this socket has handled, which is the ordinal
            DropAt counts against. */
        [[nodiscard]] uint64_t Ordinal() const noexcept
        { std::lock_guard<std::recursive_mutex> guard(mutex_); return ordinal_; }

        [[nodiscard]] common::Error Init(int port, uint32_t recvSlotCount = 4096,
                                         uint32_t sendSlotCount = 4096) override;
        void Close() override;

        [[nodiscard]] uint32_t SendBatch(const Outgoing* items, uint32_t count) override;

        [[nodiscard]] common::Error SendTo(const sockaddr_storage& target,
                                           const uint8_t* data, uint16_t size) override;

        [[nodiscard]] common::Result<uint32_t> ReceiveFrom(PacketSlotHandle* outPackets,
                                                           uint32_t maxCount) override;

    private:
        /** Guards every field below and the whole of each public operation, so
            two threads cannot interleave inside the held ring or the RNG and
            produce faults neither of them asked for. Recursive because the
            public entry points call one another. */
        mutable std::recursive_mutex mutex_;

        /** A packet the socket is sitting on, either because it was delayed or
            because it was reordered behind later ones. */
        struct Held
        {
            sockaddr_storage target{};
            uint16_t         size = 0;
            uint64_t         dueMicros = 0;   ///< release when the clock passes this
            uint32_t         releaseAfter = 0;   ///< or when this many more have gone out
            uint8_t          data[internal::MAX_WIRE_PACKET_SIZE]{};
            bool             occupied = false;
        };

        static constexpr uint32_t MAX_HELD = 64;

        Profile  profile_{};
        Stats    stats_{};
        uint64_t rng_     = 0;
        uint64_t ordinal_ = 0;

        uint32_t dropNext_    = 0;
        uint32_t corruptNext_ = 0;
        uint32_t delayNext_   = 0;
        uint32_t delayMicros_ = 0;
        uint64_t dropAt_      = UINT64_MAX;
        bool     blockHandshakes_ = false;
        uint16_t burstRemaining_  = 0;

        Held held_[MAX_HELD];
        uint16_t boundPort_ = 0;

        [[nodiscard]] uint32_t NextRandom() noexcept;
        [[nodiscard]] bool RollPercent(uint8_t percent) noexcept;
        [[nodiscard]] static bool IsHandshake(const uint8_t* data, uint16_t size) noexcept;

        /** True when this packet should not reach the wire, updating the burst
            counter and the scripted drops as it decides. */
        [[nodiscard]] bool ShouldDrop(const uint8_t* data, uint16_t size) noexcept;
        [[nodiscard]] bool Hold(const sockaddr_storage& target, const uint8_t* data,
                                uint16_t size, uint64_t dueMicros,
                                uint32_t releaseAfter) noexcept;
        void ReleaseDue() noexcept;
        [[nodiscard]] common::Error Emit(const sockaddr_storage& target,
                                         const uint8_t* data, uint16_t size) noexcept;
    };
}
