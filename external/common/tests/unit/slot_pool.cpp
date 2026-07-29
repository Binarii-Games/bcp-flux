// SlotPool integrity. Leasing hands out distinct slots until the pool is empty,
// releasing returns a slot for reuse, the read/write locks guard a slot's bytes,
// and under many threads no slot is ever leased to two at once (the case that
// matters under TSan).
#include <common/collections/slot_pool.h>

#include "harness.h"

#include <atomic>
#include <thread>
#include <vector>

using bcp::common::collections::SlotPool;

// Each lease returns a distinct slot up to capacity, then INVALID; a released
// slot is handed out again.
static void lease_hands_out_distinct_slots()
{
    SlotPool slots;
    CHECK(slots.Init(4, 64));
    CHECK(slots.GetCapacity() == 4);

    uint32_t first  = slots.Acquire();
    uint32_t second = slots.Acquire();
    uint32_t third  = slots.Acquire();
    uint32_t fourth = slots.Acquire();
    CHECK(first  != SlotPool::INVALID);
    CHECK(fourth != SlotPool::INVALID);
    CHECK(first != second && second != third && third != fourth);
    CHECK(first != third && first != fourth && second != fourth);

    CHECK(slots.Acquire() == SlotPool::INVALID);   // all four are leased out

    slots.Release(second);
    CHECK(slots.Acquire() == second);              // the freed slot comes back
}

// Bytes written under the write lock are visible under a read lock, and two
// readers hold the same slot at once (reads share the lock).
static void locks_guard_slot_bytes()
{
    SlotPool slots;
    CHECK(slots.Init(2, 16));

    uint32_t slot = slots.Acquire();
    CHECK(slot != SlotPool::INVALID);

    uint8_t* writable = slots.WriteLock(slot);
    CHECK(writable != nullptr);
    writable[0] = 0xAB;
    writable[1] = 0xCD;
    slots.UnlockWrite(slot);

    const uint8_t* readerA = slots.ReadLock(slot);
    const uint8_t* readerB = slots.ReadLock(slot);
    CHECK(readerA != nullptr && readerB != nullptr);   // readers overlap
    CHECK(readerA[0] == 0xAB && readerA[1] == 0xCD);
    slots.UnlockRead(slot);
    slots.UnlockRead(slot);
}

// Under concurrent lease/release a slot index is never held by two threads at
// once. Each thread claims its slot in a shared ownership table and checks it
// was free; a double-claim trips the flag.
static void concurrent_leases_stay_exclusive()
{
    constexpr uint32_t CAPACITY = 64;
    constexpr int      THREADS  = 8;
    constexpr int      ROUNDS   = 20000;

    SlotPool slots;
    CHECK(slots.Init(CAPACITY, 8));

    std::vector<std::atomic<int>> owner(CAPACITY);
    for (auto& cell : owner) cell.store(-1);
    std::atomic<bool> doubleClaimed{false};

    auto hammer = [&](int threadId)
    {
        for (int round = 0; round < ROUNDS; ++round)
        {
            uint32_t slot = slots.Acquire();
            if (slot == SlotPool::INVALID) continue;   // pool momentarily empty

            int wasFree = -1;
            if (!owner[slot].compare_exchange_strong(wasFree, threadId))
                doubleClaimed = true;                  // another thread held it
            owner[slot].store(-1);
            slots.Release(slot);
        }
    };

    std::vector<std::thread> workers;
    for (int i = 0; i < THREADS; ++i) workers.emplace_back(hammer, i);
    for (auto& worker : workers) worker.join();

    CHECK(!doubleClaimed);
}

int main()
{
    lease_hands_out_distinct_slots();
    locks_guard_slot_bytes();
    concurrent_leases_stay_exclusive();
    return test::report();
}
