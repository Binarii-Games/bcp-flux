// --- slot_pool.h ---

#pragma once

#include <atomic>
#include <cstdint>
#include <cassert>

#include <common/platform.h>

namespace bcp::common::collections 
{
    /** Lock-free slot pool: a sharded index free-list + contiguous memory +
        per-slot RW locks. Backs the retransmit store, holding packet data
        multiple threads access.

        The free list is not one ring but up to SHARD_COUNT independent MPMC
        rings, each permanently owning the indices of its residue class (index
        i lives in ring i % shardCount, forever). Concurrent acquires and
        releases spread across that many separate cache-line pairs instead of
        all colliding on one. Acquire starts at a ring picked from a per-thread
        hint (a hashed stack address: distinct and stable per thread, with no
        thread identity or thread_local required) and hops to the next ring
        when one runs empty, so the hint is a performance input, never a
        correctness one. Release returns an index to its home ring: a ring can
        hold at most the indices it owns, so it can be exactly full but never
        over-full, and a release that finds its cell unready is only ever
        waiting out a consumer a few instructions from publishing.
     */
    class SlotPool {
    private:
        struct alignas(CACHE_LINE) RingCell {
            std::atomic<uint32_t> sequence;
            uint32_t idx;
        };

        struct alignas(CACHE_LINE) SlotRWLock {
            std::atomic<uint32_t> state{0};
        };

        /** One ring's cursors. head (Release side) and tail (Acquire side) sit
            on separate cache lines so the two directions never false-share. */
        struct ShardCtl {
            alignas(CACHE_LINE) std::atomic<uint32_t> head{0};
            alignas(CACHE_LINE) std::atomic<uint32_t> tail{0};
        };

        /** Free-list rings. Contention drops with each doubling until threads
            no longer collide; 16 covers the worker counts the sockets run at
            ~4 KB of control state. A pool smaller than this gets one ring per
            index. */
        static constexpr uint32_t SHARD_COUNT = 16;

        static constexpr uint32_t WRITE_LOCKED = 0xFFFFFFFF;
        static constexpr uint32_t MAX_READERS  = 0xFFFFFFFE;

        uint8_t*    memory_   = nullptr;
        uint32_t    stride_   = 0;
        uint32_t    capacity_ = 0;

        RingCell*   ring_     = nullptr;   ///< capacity_ cells; ring r owns [r*perCap_, (r+1)*perCap_)
        ShardCtl*   shards_   = nullptr;   ///< shardCount_ cursor pairs
        uint32_t    shardCount_ = 0;       ///< power of two: min(SHARD_COUNT, capacity_)
        uint32_t    shardMask_  = 0;
        uint32_t    perCap_     = 0;       ///< indices (and cells) per ring, power of two
        uint32_t    perMask_    = 0;

        SlotRWLock* locks_    = nullptr;

        /** One counter per slot, advanced by every release. Not aligned per
            entry like the locks: a release is rare next to the lock traffic a
            slot sees, so sharing lines costs nothing that matters. */
        std::atomic<uint32_t>* generations_ = nullptr;

    public:
        static constexpr uint32_t INVALID = UINT32_MAX;

        SlotPool() = default;
        ~SlotPool();

        SlotPool(const SlotPool&) = delete;
        SlotPool& operator=(const SlotPool&) = delete;

        [[nodiscard]] bool Init(uint32_t capacity, uint32_t slotSize);
        void Shutdown();

        // Index management
        [[nodiscard]] uint32_t Acquire();
        void Release(uint32_t idx);

        /** Release, guarded by the slot's generation. Frees the slot only when
            `expectedGen` is the generation currently on it, advancing it in the
            same atomic step, so of two racing releases carrying the same pair
            exactly one frees and the other is refused. False refuses: the pair
            is stale (the slot was already released, perhaps re-acquired) or the
            index is out of range, and nothing was freed.

            For indices that leave the process, where the caller's discipline
            cannot be trusted the way a destructor can. A double release through
            the plain overload does not merely corrupt: the home ring becomes
            over-full and the next release on it spins forever. */
        [[nodiscard]] bool Release(uint32_t idx, uint32_t expectedGen);

        /** The generation currently on a slot: advanced by every release, so a
            (index, generation) pair taken while holding the slot names this
            tenancy and no other. 0 for an out-of-range index. */
        [[nodiscard]] uint32_t GenerationOf(uint32_t idx) const;

        // Per-slot locking: readers can overlap, writer is exclusive
        const uint8_t* ReadLock(uint32_t idx);
        uint8_t*       WriteLock(uint32_t idx);
        void           UnlockRead(uint32_t idx);
        void           UnlockWrite(uint32_t idx);
        void           DowngradeLock(uint32_t idx);

        // Direct slot access; caller is responsible for synchronization
        uint8_t* GetSlotPtr(uint32_t idx);
        const uint8_t* GetSlotPtr(uint32_t idx) const;

        uint32_t GetCapacity() const { return capacity_; }
        uint32_t GetStride()   const { return stride_; }

    private:
        /** One Vyukov take on ring `ring`. INVALID means that ring is empty
            right now; the caller hops to the next. */
        [[nodiscard]] uint32_t TryAcquireFrom(uint32_t ring) noexcept;

        /** Returns the index to its home ring. The generation is the caller's
            business and must already be advanced. */
        void PushFree(uint32_t idx) noexcept;
    };
}