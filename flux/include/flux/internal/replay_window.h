#pragma once

#include <cstdint>

namespace bcp::flux
{
    /** Sliding-window replay filter over a peer's received nonce counters.
        A genuine secure packet is accepted once; a duplicate or a counter
        older than the window is rejected; out-of-order delivery within the
        window is tolerated (UDP reorders).

        Non-owning view. The caller owns the storage and passes a block of
        (1 + words) uint64: state[0] is the high-water mark (highest counter
        accepted, 0 = none yet) and state[1..words] is the seen-bitmap, where
        bit i marks counter (highWater - i).

        Counters come from the per-peer send counter in each secure packet's
        nonce. The sender's first counter is 1 (PreProcessOut does ++counter),
        so 0 is reserved to mean "nothing seen yet" and is always rejected.

        @pre Caller holds the peer's write lock across every call. ReplayWindow
             takes no lock and is not itself thread-safe. */
    struct ReplayWindow
    {
        uint64_t* state;   ///< [0] = highWater; [1 .. words] = seen-bitmap
        uint32_t  words;   ///< bitmap words; the window covers words * 64 counters

        /** Zeroes the high-water mark and the bitmap. Call on every session
            re-key: both sides restart their counter at 0, so a stale watermark
            would reject every fresh packet as too old. */
        void Reset() noexcept;

        /** Records counter as received, marking it when new.

            @return false (drop the packet) when counter is a duplicate, older
                    than the window, or 0; true when it is new.
            @pre Packet has already authenticated (decrypted). A forgery must
                 never advance the window. */
        [[nodiscard]] bool Accept(uint64_t counter) noexcept;
    };
}
