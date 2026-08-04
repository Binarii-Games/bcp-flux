#pragma once

#include <atomic>
#include <cstdint>

#include <common/platform.h>

namespace bcp::flux
{
    /** What one peer currently costs this socket's receive pool, and what it was
        told it may cost.

        One of these per peer slot, in a flat array beside the peer table rather
        than as fields on `Peer`. Both are written on the receive path, which
        does not hold the peer lock, and `Peer` has to stay trivially copyable.

        Neither field publishes anything. Slot ownership is carried by the
        handles and the pool's free list, which have their own ordering, and no
        thread reads either value and then touches memory whose visibility
        depends on it. They are only ever compared. So every access here is
        relaxed, and that reasoning is what any future change has to preserve.

        A reader may therefore see a value stale by however many pins and
        releases are in flight, bounded by the number of threads. The cost is a
        peer admitted a packet or two past its limit, or shed a packet or two
        early. It can never over-allocate the pool, leak a slot or double
        release one, because the count decides policy and never ownership. The
        pool's own capacity remains the hard bound.

        Padded because adjacent peer slots are served by different threads and
        would otherwise share a line. */
    struct alignas(common::CACHE_LINE) PeerRecvState
    {
        /** Recv slots this peer pins right now, whether held in a flow's
            reorder hold-back or queued for delivery and not yet polled. Both
            pin a slot, so both count. */
        std::atomic<uint32_t> occupancy{0};

        /** What this socket told the peer it may occupy at once. Zero until a
            grant is negotiated, and nothing reads it yet. */
        std::atomic<uint32_t> grant{0};

        /** Times this peer has had buffered packets thrown away for making no
            progress. A gap a sender fills costs nothing here. A gap it never
            fills, repeatedly, is a peer holding buffer it is not using, which
            is the one abuse a well-behaved remote never commits. Counted here
            because the reclaim runs without the peer lock. */
        std::atomic<uint32_t> stallReclaims{0};

        void PinOne() noexcept { occupancy.fetch_add(1, std::memory_order_relaxed); }

        /** Saturates at zero instead of wrapping.

            A peer slot can be reused while a packet belonging to its previous
            occupant is still queued, and releasing that packet then lands here.
            A plain fetch_sub at zero would wrap to four billion, which reads as
            an unlimited grant. Saturating leaves the successor undercounted by
            however many of its predecessor's packets were still in flight,
            which self corrects as it drains. */
        void ReleaseOne() noexcept
        {
            uint32_t current = occupancy.load(std::memory_order_relaxed);
            while (current > 0
                   && !occupancy.compare_exchange_weak(current, current - 1,
                                                       std::memory_order_relaxed,
                                                       std::memory_order_relaxed))
            {
            }
        }

        /** Wipes both fields for a new occupant of this slot. */
        void Reset() noexcept
        {
            occupancy.store(0, std::memory_order_relaxed);
            grant.store(0, std::memory_order_relaxed);
            stallReclaims.store(0, std::memory_order_relaxed);
        }
    };
}
