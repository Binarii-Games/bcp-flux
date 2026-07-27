// --- slot_pool.cpp ---

#include <common/collections/slot_pool.h>

#include <cstring>
#include <new>

#include <common/math.h>
#include <common/log.h>

namespace bcp::common::collections {

    /** Starting-ring hint: the address of a stack local, hashed. Each thread
        has its own stack, so the value is distinct and stable per thread and
        costs a few ALU ops — no thread id, no thread_local, no teardown. A
        collision only means two threads share a starting ring, which the hop
        absorbs; the hint never affects correctness. */
    static inline uint32_t ShardHint() noexcept {
        char probe;
        uint32_t h = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(&probe) >> 6);
        h ^= h >> 16; h *= 0x7feb352dU;
        h ^= h >> 15; h *= 0x846ca68bU;
        h ^= h >> 16;
        return h;
    }

    SlotPool::~SlotPool() {
        Shutdown();
    }

    bool SlotPool::Init(uint32_t capacity, uint32_t slotSize) {
        capacity_ = NextPowerOfTwo(capacity);
        stride_   = slotSize;

        // Both powers of two, so every ring gets the same whole number of
        // indices and the residue map (idx & shardMask_) partitions exactly.
        shardCount_ = capacity_ < SHARD_COUNT ? capacity_ : SHARD_COUNT;
        shardMask_  = shardCount_ - 1;
        perCap_     = capacity_ / shardCount_;
        perMask_    = perCap_ - 1;

        memory_ = static_cast<uint8_t*>(
            ::operator new(capacity_ * stride_, std::align_val_t(CACHE_LINE))
        );
        if (!memory_) return false;
        std::memset(memory_, 0, capacity_ * stride_);

        ring_ = static_cast<RingCell*>(
            ::operator new(capacity_ * sizeof(RingCell), std::align_val_t(CACHE_LINE))
        );
        if (!ring_) {
            ::operator delete(memory_, std::align_val_t(CACHE_LINE));
            memory_ = nullptr;
            return false;
        }

        shards_ = static_cast<ShardCtl*>(
            ::operator new(shardCount_ * sizeof(ShardCtl), std::align_val_t(CACHE_LINE))
        );
        if (!shards_) {
            ::operator delete(memory_, std::align_val_t(CACHE_LINE));
            memory_ = nullptr;
            ::operator delete(ring_, std::align_val_t(CACHE_LINE));
            ring_ = nullptr;
            return false;
        }

        // Ring r starts full of its own residue class: r, r+shardCount, ...
        for (uint32_t r = 0; r < shardCount_; r++) {
            new(&shards_[r]) ShardCtl();
            RingCell* cells = ring_ + static_cast<size_t>(r) * perCap_;
            for (uint32_t k = 0; k < perCap_; k++) {
                cells[k].sequence.store(k + 1, std::memory_order_relaxed);
                cells[k].idx = r + k * shardCount_;
            }
            shards_[r].head.store(perCap_, std::memory_order_relaxed);
            shards_[r].tail.store(0, std::memory_order_relaxed);
        }

        locks_ = static_cast<SlotRWLock*>(
            ::operator new(capacity_ * sizeof(SlotRWLock), std::align_val_t(CACHE_LINE))
        );
        if (!locks_) {
            ::operator delete(memory_, std::align_val_t(CACHE_LINE));
            memory_ = nullptr;
            ::operator delete(ring_, std::align_val_t(CACHE_LINE));
            ring_ = nullptr;
            ::operator delete(shards_, std::align_val_t(CACHE_LINE));
            shards_ = nullptr;
            return false;
        }
        for (uint32_t i = 0; i < capacity_; i++) {
            new(&locks_[i]) SlotRWLock();
        }

        return true;
    }

    void SlotPool::Shutdown() {
        if (ring_) {
            ::operator delete(ring_, std::align_val_t(CACHE_LINE));
            ring_ = nullptr;
        }

        if (shards_) {
            for (uint32_t r = 0; r < shardCount_; r++)
                shards_[r].~ShardCtl();
            ::operator delete(shards_, std::align_val_t(CACHE_LINE));
            shards_ = nullptr;
        }

        if (locks_) {
            for (uint32_t i = 0; i < capacity_; i++)
                locks_[i].~SlotRWLock();
            ::operator delete(locks_, std::align_val_t(CACHE_LINE));
            locks_ = nullptr;
        }

        if (memory_) {
            ::operator delete(memory_, std::align_val_t(CACHE_LINE));
            memory_ = nullptr;
        }

        capacity_ = 0;
        stride_ = 0;
        shardCount_ = 0;
        shardMask_ = 0;
        perCap_ = 0;
        perMask_ = 0;
    }

    uint32_t SlotPool::TryAcquireFrom(uint32_t ring) noexcept {
        ShardCtl& ctl   = shards_[ring];
        RingCell* cells = ring_ + static_cast<size_t>(ring) * perCap_;

        uint32_t tail = ctl.tail.load(std::memory_order_acquire);
        for (;;) {
            RingCell& cell = cells[tail & perMask_];
            uint32_t seq = cell.sequence.load(std::memory_order_acquire);
            int32_t diff = static_cast<int32_t>(seq) - static_cast<int32_t>(tail + 1);

            if (diff == 0) {
                if (ctl.tail.compare_exchange_weak(tail, tail + 1, std::memory_order_acquire)) {
                    uint32_t idx = cell.idx;
                    cell.sequence.store(tail + perMask_ + 1, std::memory_order_release);
                    return idx;
                }
            } else if (diff < 0) {
                return INVALID;
            } else {
                CpuPause();
                tail = ctl.tail.load(std::memory_order_acquire);
            }
        }
    }

    uint32_t SlotPool::Acquire() {
        const uint32_t start = ShardHint() & shardMask_;
        for (uint32_t hop = 0; hop < shardCount_; hop++) {
            uint32_t idx = TryAcquireFrom((start + hop) & shardMask_);
            if (idx != INVALID) return idx;
        }
        return INVALID;
    }

    uint32_t SlotPool::AcquireBatch(uint32_t* indices, uint32_t requestedCount) {
        // Gathers ring by ring from the hint onward; the batch may span rings.
        // Like Acquire, a full sweep finding nothing returns what was got.
        uint32_t got = 0;
        const uint32_t start = ShardHint() & shardMask_;
        for (uint32_t hop = 0; hop < shardCount_ && got < requestedCount; hop++) {
            const uint32_t ring = (start + hop) & shardMask_;
            while (got < requestedCount) {
                uint32_t idx = TryAcquireFrom(ring);
                if (idx == INVALID) break;
                indices[got++] = idx;
            }
        }
        return got;
    }

    void SlotPool::Release(uint32_t idx) {
        // The index picks the ring, not the caller: its home holds only its
        // own residue class, so the ring can be exactly full but never
        // over-full, and the wait below is always short.
        ShardCtl& ctl   = shards_[idx & shardMask_];
        RingCell* cells = ring_ + static_cast<size_t>(idx & shardMask_) * perCap_;

        uint32_t head = ctl.head.load(std::memory_order_acquire);
        for (;;) {
            RingCell& cell = cells[head & perMask_];
            uint32_t seq = cell.sequence.load(std::memory_order_acquire);
            int32_t diff = static_cast<int32_t>(seq) - static_cast<int32_t>(head);

            if (diff == 0) {
                if (ctl.head.compare_exchange_weak(head, head + 1, std::memory_order_acquire)) {
                    cell.idx = idx;
                    cell.sequence.store(head + 1, std::memory_order_release);
                    return;
                }
            } else {
                // diff > 0: our head snapshot is stale. diff < 0: the consumer
                // that claimed this cell has advanced tail but not yet
                // published its sequence. Both are transient — every acquired
                // index has a cell arithmetically reserved for its return, so
                // the cell always materializes; wait for it. Bailing out here
                // instead would leak the index from the pool permanently.
                CpuPause();
                head = ctl.head.load(std::memory_order_acquire);
            }
        }
    }

    void SlotPool::ReleaseBatch(const uint32_t* indices, uint32_t count) {
        // A batch's indices can be homed to different rings, so each one is
        // routed individually. Release never drops, so neither does this.
        for (uint32_t i = 0; i < count; i++)
            Release(indices[i]);
    }

    // Per-slot locking: multiple readers, single writer
    const uint8_t* SlotPool::ReadLock(uint32_t idx) 
    {
        auto& s = locks_[idx].state;
        for (;;) {
            uint32_t cur = s.load(std::memory_order_relaxed);
            if (cur == WRITE_LOCKED || cur >= MAX_READERS) {
                CpuPause();
                continue;
            }
            if (s.compare_exchange_weak(cur, cur + 1, std::memory_order_acquire, std::memory_order_relaxed))
                return GetSlotPtr(idx);
        }
    }

    uint8_t* SlotPool::WriteLock(uint32_t idx) 
    {
        auto& s = locks_[idx].state;
        for (;;) {
            uint32_t expected = 0;
            if (s.compare_exchange_weak(expected, WRITE_LOCKED, std::memory_order_acquire, std::memory_order_relaxed))
                return GetSlotPtr(idx);
            CpuPause();
        }
    }

    void SlotPool::UnlockRead(uint32_t idx) {
        locks_[idx].state.fetch_sub(1, std::memory_order_release);
    }

    void SlotPool::UnlockWrite(uint32_t idx) 
    {
        locks_[idx].state.store(0, std::memory_order_release);
    }

    void SlotPool::DowngradeLock(uint32_t idx)
    {
        uint32_t expected = WRITE_LOCKED;
        locks_[idx].state.compare_exchange_strong(expected, 1, std::memory_order_release, std::memory_order_relaxed);
    }

    // Direct access: no locking, caller manages synchronization
    uint8_t* SlotPool::GetSlotPtr(uint32_t idx) 
    {
        assert(idx < capacity_);
        return memory_ + (static_cast<size_t>(idx) * stride_);
    }

    const uint8_t* SlotPool::GetSlotPtr(uint32_t idx) const 
    {
        assert(idx < capacity_);
        return memory_ + (static_cast<size_t>(idx) * stride_);
    }
}