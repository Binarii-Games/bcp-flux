#pragma once

#include <cstddef>
#include <cstdint>

#include <atomic>

#include <common/collections/fifo_queue.h>

namespace bcp::flux
{
    /** The queues delivered packets wait in, split so that one thread drains
        each.

        A flow is ordered into its queue already: the delivery cursor only
        advances under the association's write lock, and the packet is pushed
        under that same hold, so what goes in is in sequence. One queue drained
        by several threads throws that away at the pop, because each thread
        takes whatever it wins and hands it to the application immediately.
        Splitting by peer restores it: everything from one peer lands in one
        queue, that queue has one consumer, and the sequence the receiver built
        is the sequence the application sees.

        A flow packet's lane comes from the peer's slot index, which never
        changes while the peer lives, so a peer that moves to a new address keeps
        its lane and nothing has to be handed between threads. A packet with no
        flow carries no sequence and so has no order to keep: it takes the lane
        its source address hashes to, which only keeps one sender's traffic
        landing together. The multiply is a Fibonacci hash, because pool slots
        come off a sharded free list and their low bits carry the shard rather
        than anything uniform.

        Each lane is sized for the whole receive pool rather than a share of it.
        All the traffic can come from peers landing in one lane, and a push that
        can fail is a packet dropped after the sender was told it arrived.

        A lane is claimed for as long as its packets are being read, not merely
        while they are drained, because the order only survives if one thread is
        the only one working that peer's traffic from the pop through to the
        last byte the application reads. Any thread may claim any lane, so a lane
        is never left to fill because the thread that owned it stopped calling.
        A claim starts at the lane the caller last held: that keeps a thread on
        one lane and its peers' state in one cache while things are healthy, and
        lets another thread take it over when they are not. */
    /** A packet waiting to be polled. The peer slot rides with it because the
        thread that pops it has to know whose receive budget it frees, and by
        then the packet's association is long out of reach. Eight bytes in a
        cell that is cache-line padded either way, so it costs nothing. */
    struct ReadyEntry
    {
        uint32_t slotIndex;
        uint32_t peerSlot;
    };

    class ReadyLanes
    {
    public:
        /** Ceiling on lanes, and therefore on polling threads. */
        static constexpr uint32_t MAX_LANES = 16;

        ReadyLanes() = default;
        ~ReadyLanes() { Shutdown(); }

        ReadyLanes(const ReadyLanes&) = delete;
        ReadyLanes& operator=(const ReadyLanes&) = delete;

        /** @param laneCount a power of two, at most MAX_LANES. A caller that
                   passes anything else gets it rounded up, which is why Socket
                   refuses such a count before reaching here: a rounded one
                   leaves a lane nobody was told to drain.
            @param perLaneCapacity entries in each lane, one per receive slot so
                   a push cannot fail. */
        [[nodiscard]] bool Init(uint32_t laneCount, uint32_t perLaneCapacity) noexcept;
        void Shutdown() noexcept;

        [[nodiscard]] uint32_t LaneCount() const noexcept { return laneCount_; }

        /** Takes a lane for the caller, preferring `wanted`.

            @return the lane claimed, or NO_LANE when every one is busy. */
        [[nodiscard]] uint32_t ClaimLane(uint32_t wanted) noexcept;

        /** Hands a claimed lane back. */
        void ReleaseLane(uint32_t lane) noexcept
        {
            if (lane < laneCount_) busy_[lane].flag.clear(std::memory_order_release);
        }

        static constexpr uint32_t NO_LANE = 0xFFFFFFFFu;

        /** Which lane a key belongs in. Callers pass a peer slot index for
            flow traffic and an address hash for everything else. */
        [[nodiscard]] uint32_t LaneOf(uint32_t key) const noexcept
        {
            return laneCount_ > 1 ? (key * GOLDEN) >> laneShift_ : 0;
        }

        [[nodiscard]] bool Push(uint32_t lane, uint32_t slotIndex, uint32_t peerSlot) noexcept
        {
            return lane < laneCount_ && lanes_[lane].Push(ReadyEntry{slotIndex, peerSlot});
        }

        [[nodiscard]] bool Pop(uint32_t lane, ReadyEntry& out) noexcept
        {
            return lane < laneCount_ && lanes_[lane].Pop(out);
        }

    private:
        static constexpr uint32_t GOLDEN = 0x9E3779B1u;

        /** One flag per lane, padded apart so claiming one lane does not
            bounce the cache line another lane's claim sits on. */
        struct alignas(common::CACHE_LINE) LaneBusy
        {
            std::atomic_flag flag = ATOMIC_FLAG_INIT;
        };

        common::collections::FifoQueue<ReadyEntry> lanes_[MAX_LANES];
        LaneBusy busy_[MAX_LANES];
        uint32_t laneCount_ = 0;
        uint32_t laneShift_ = 32;
    };
}
