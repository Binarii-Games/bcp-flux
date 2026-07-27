// FifoQueue integrity. Items come out in the order they went in, a full queue
// refuses a push and an empty one refuses a pop, the batch calls move several
// at once, and under many producers and consumers every item is delivered
// exactly once — none lost, none duplicated (the case that matters under TSan).
#include <common/collections/fifo_queue.h>

#include "harness.h"

#include <atomic>
#include <thread>
#include <vector>

using bcp::common::collections::FifoQueue;

// Pushed values pop back in first-in-first-out order.
static void pops_in_push_order()
{
    FifoQueue<uint32_t> queue;
    CHECK(queue.Init(8));
    CHECK(queue.Empty());

    for (uint32_t value = 0; value < 8; ++value)
        CHECK(queue.Push(value));

    for (uint32_t expected = 0; expected < 8; ++expected)
    {
        uint32_t popped = 0;
        CHECK(queue.Pop(popped));
        CHECK(popped == expected);
    }
    CHECK(queue.Empty());
}

// A full queue refuses another push; an empty queue refuses a pop. Init rounds
// capacity up to a power of two, so the queue holds exactly that many.
static void full_refuses_push_empty_refuses_pop()
{
    FifoQueue<uint32_t> queue;
    CHECK(queue.Init(4));
    CHECK(queue.GetCapacity() == 4);

    uint32_t drained = 0;
    CHECK(!queue.Pop(drained));               // empty: nothing to pop

    for (uint32_t value = 0; value < 4; ++value)
        CHECK(queue.Push(value));
    CHECK(!queue.Push(99));                    // full: capacity reached

    CHECK(queue.Pop(drained) && drained == 0); // freeing one slot...
    CHECK(queue.Push(99));                      // ...lets a push through again
}

// PushBatch and PopBatch move several items in one call, preserving order.
static void batch_moves_several_at_once()
{
    FifoQueue<uint32_t> queue;
    CHECK(queue.Init(16));

    uint32_t input[5] = {10, 20, 30, 40, 50};
    CHECK(queue.PushBatch(input, 5) == 5);

    uint32_t output[5] = {0};
    CHECK(queue.PopBatch(output, 5) == 5);
    for (int i = 0; i < 5; ++i)
        CHECK(output[i] == input[i]);
}

// Under concurrent producers and consumers every value is delivered exactly
// once. Producers push distinct values; consumers record each into a shared
// table. At the end every value must have been seen exactly once.
static void concurrent_delivers_each_once()
{
    constexpr int      PRODUCERS = 4;
    constexpr int      CONSUMERS = 4;
    constexpr uint32_t PER       = 20000;
    constexpr uint32_t TOTAL     = PRODUCERS * PER;

    FifoQueue<uint32_t> queue;
    CHECK(queue.Init(1024));

    std::vector<std::atomic<int>> seen(TOTAL);
    for (auto& cell : seen) cell.store(0);
    std::atomic<int>      producersDone{0};
    std::atomic<uint32_t> delivered{0};

    auto produce = [&](int producerId)
    {
        uint32_t base = static_cast<uint32_t>(producerId) * PER;
        for (uint32_t i = 0; i < PER; ++i)
            while (!queue.Push(base + i)) std::this_thread::yield();   // spin while full
        ++producersDone;
    };

    auto consume = [&]()
    {
        for (;;)
        {
            uint32_t value = 0;
            if (queue.Pop(value))
            {
                seen[value].fetch_add(1);
                delivered.fetch_add(1);
            }
            else if (producersDone.load() == PRODUCERS && queue.Empty())
            {
                break;   // producers finished and nothing left to drain
            }
            else
            {
                std::this_thread::yield();
            }
        }
    };

    std::vector<std::thread> threads;
    for (int i = 0; i < PRODUCERS; ++i) threads.emplace_back(produce, i);
    for (int i = 0; i < CONSUMERS; ++i) threads.emplace_back(consume);
    for (auto& thread : threads) thread.join();

    CHECK(delivered.load() == TOTAL);
    bool everyValueOnce = true;
    for (auto& cell : seen)
        if (cell.load() != 1) everyValueOnce = false;
    CHECK(everyValueOnce);
}

int main()
{
    pops_in_push_order();
    full_refuses_push_empty_refuses_pop();
    batch_moves_several_at_once();
    concurrent_delivers_each_once();
    return test::report();
}
