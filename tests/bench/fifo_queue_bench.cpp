// FifoQueue throughput against two baselines: std::mutex + std::queue (the
// default reach) and std::mutex + fixed ring (bounded and allocation-free,
// the same constraints FifoQueue lives under). Single-thread round trip, then
// contended with equal producers and consumers.
//
// Consumers pop an exact share of the total and never poll Empty(): an
// emptiness probe is a second lock acquisition for a mutex queue, so putting
// it in the loop would bias the comparison. Only Push and Pop are on the
// clock, for every contender.
//
// FifoQueue is one Vyukov ring. Strict FIFO is its contract, which rules out
// the sharding that spreads SlotPool's contention across independent rings —
// so once CAS collisions dominate, the mutex convoy wins on throughput. The
// numbers below show where that crossover sits on this machine.
#include <common/collections/fifo_queue.h>

#include "bench_harness.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>

using bcp::common::collections::FifoQueue;

// Baseline 1: a mutex around std::queue. Unbounded, allocates per push.
struct MutexQueue
{
    std::mutex           mutex;
    std::queue<uint32_t> queue;

    bool Push(uint32_t value)
    {
        std::lock_guard<std::mutex> guard(mutex);
        queue.push(value);
        return true;
    }
    bool Pop(uint32_t& value)
    {
        std::lock_guard<std::mutex> guard(mutex);
        if (queue.empty()) return false;
        value = queue.front();
        queue.pop();
        return true;
    }
};

// Baseline 2: a mutex around a fixed ring — bounded and allocation-free, the
// constraints FifoQueue actually competes under.
struct MutexRing
{
    std::mutex            mutex;
    std::vector<uint32_t> cells;
    uint32_t              mask = 0, head = 0, tail = 0;

    void Init(uint32_t capacity)
    {
        cells.resize(capacity);
        mask = capacity - 1;
    }
    bool Push(uint32_t value)
    {
        std::lock_guard<std::mutex> guard(mutex);
        if (tail - head == cells.size()) return false;
        cells[tail++ & mask] = value;
        return true;
    }
    bool Pop(uint32_t& value)
    {
        std::lock_guard<std::mutex> guard(mutex);
        if (head == tail) return false;
        value = cells[head++ & mask];
        return true;
    }
};

static void single_thread_round_trip()
{
    constexpr uint64_t ITERATIONS = 5'000'000;

    FifoQueue<uint32_t> ours;
    (void)ours.Init(4096);
    double oursNs = bench::ns_per_op(ITERATIONS, 100000, [&]
    {
        (void)ours.Push(7);
        uint32_t value = 0;
        (void)ours.Pop(value);
        bench::sink += value;
    });

    MutexQueue stdQueue;
    double stdNs = bench::ns_per_op(ITERATIONS, 100000, [&]
    {
        (void)stdQueue.Push(7);
        uint32_t value = 0;
        (void)stdQueue.Pop(value);
        bench::sink += value;
    });

    MutexRing ring;
    ring.Init(4096);
    double ringNs = bench::ns_per_op(ITERATIONS, 100000, [&]
    {
        (void)ring.Push(7);
        uint32_t value = 0;
        (void)ring.Pop(value);
        bench::sink += value;
    });

    bench::compare("push+pop vs std::queue", oursNs, stdNs);
    bench::compare("push+pop vs fixed ring", oursNs, ringNs);
}

// `producers` threads each push `perProducer` values; `consumers` threads each
// pop an exact share of the total. Returns wall-clock seconds.
template <typename Queue>
static double run_contended(Queue& queue, int producers, int consumers, uint64_t perProducer)
{
    const uint64_t total       = static_cast<uint64_t>(producers) * perProducer;
    const uint64_t perConsumer = total / static_cast<uint64_t>(consumers);

    std::atomic<bool> go{false};
    std::vector<std::thread> threads;

    for (int p = 0; p < producers; ++p)
        threads.emplace_back([&]
        {
            while (!go.load(std::memory_order_acquire)) std::this_thread::yield();
            for (uint64_t i = 0; i < perProducer; ++i)
                while (!queue.Push(static_cast<uint32_t>(i))) std::this_thread::yield();
        });

    for (int c = 0; c < consumers; ++c)
        threads.emplace_back([&]
        {
            while (!go.load(std::memory_order_acquire)) std::this_thread::yield();
            uint64_t local = 0;
            for (uint64_t i = 0; i < perConsumer; ++i)
            {
                uint32_t value = 0;
                while (!queue.Pop(value)) std::this_thread::yield();
                local += value;
            }
            bench::sink += local;
        });

    auto start = std::chrono::steady_clock::now();
    go.store(true, std::memory_order_release);
    for (auto& t : threads) t.join();
    auto end = std::chrono::steady_clock::now();

    return std::chrono::duration<double>(end - start).count();
}

static void contended_throughput()
{
    constexpr uint64_t PER = 400'000;

    for (int perSide : {1, 2, 4, 8})
    {
        uint64_t total = static_cast<uint64_t>(perSide) * PER;

        FifoQueue<uint32_t> ours;
        (void)ours.Init(8192);
        double oursSeconds = run_contended(ours, perSide, perSide, PER);
        bench::throughput("fifo_queue", total, oursSeconds, perSide * 2);

        MutexQueue stdQueue;
        double stdSeconds = run_contended(stdQueue, perSide, perSide, PER);
        bench::throughput("mutex_std_queue", total, stdSeconds, perSide * 2);

        MutexRing ring;
        ring.Init(8192);
        double ringSeconds = run_contended(ring, perSide, perSide, PER);
        bench::throughput("mutex_fixed_ring", total, ringSeconds, perSide * 2);
    }
}

int main()
{
    std::printf("FifoQueue vs std::mutex + std::queue and std::mutex + fixed ring\n");
    single_thread_round_trip();
    contended_throughput();
    return 0;
}
