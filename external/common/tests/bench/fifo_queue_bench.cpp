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

// Unrelated work between operations. The only FifoQueue in flux is the socket's
// ready queue, and between two of its operations Poll does a recvfrom and an
// AEAD open — microseconds, not nothing. A queue that is hammered with zero
// spacing measures a workload no caller produces, so the sweep below reports
// both that ceiling and the spacing a packet path actually has.
static uint64_t dependent_work(uint64_t rounds, uint64_t seed)
{
    uint64_t x = seed;
    for (uint64_t i = 0; i < rounds; ++i)
        x = x * 6364136223846793005ULL + 1442695040888963407ULL;
    return x;
}

// Every thread pushes and pops, which is the shape the ready queue has: Poll
// pass 1 enqueues and pass 2 drains, both on whichever thread called Poll.
// Nothing polls Empty(): on a mutex queue that is a second lock acquisition per
// miss, so putting it in the loop would bias the comparison toward the
// lock-free side. Only Push and Pop are on the clock, for every contender.
template <typename Queue>
static double run_contended(Queue& queue, int threads, uint64_t perThread, uint64_t workRounds)
{
    std::atomic<bool> go{false};
    std::vector<std::thread> workers;

    for (int t = 0; t < threads; ++t)
        workers.emplace_back([&, t]
        {
            uint64_t local = static_cast<uint64_t>(t);
            while (!go.load(std::memory_order_acquire)) std::this_thread::yield();
            for (uint64_t i = 0; i < perThread; ++i)
            {
                if (workRounds) local += dependent_work(workRounds, local);
                (void)queue.Push(static_cast<uint32_t>(i));
                if (workRounds) local += dependent_work(workRounds, local);
                uint32_t value = 0;
                if (queue.Pop(value)) local += value;
            }
            bench::sink += local;
        });

    auto start = std::chrono::steady_clock::now();
    go.store(true, std::memory_order_release);
    for (auto& t : workers) t.join();
    auto end = std::chrono::steady_clock::now();

    return std::chrono::duration<double>(end - start).count();
}

static void contended_regime(const char* title, uint64_t workRounds, uint64_t perThread)
{
    std::printf("  --- %s ---\n", title);
    for (int threads : {2, 4, 8, 16})
    {
        const uint64_t total = static_cast<uint64_t>(threads) * perThread;

        FifoQueue<uint32_t> ours;
        (void)ours.Init(8192);
        bench::throughput("fifo_queue", total,
                          run_contended(ours, threads, perThread, workRounds), threads);

        MutexQueue stdQueue;
        bench::throughput("mutex_std_queue", total,
                          run_contended(stdQueue, threads, perThread, workRounds), threads);

        MutexRing ring;
        ring.Init(8192);
        bench::throughput("mutex_fixed_ring", total,
                          run_contended(ring, threads, perThread, workRounds), threads);
    }
}

int main()
{
    std::printf("FifoQueue vs std::mutex + std::queue and std::mutex + fixed ring\n");
    single_thread_round_trip();
    contended_regime("no work between ops (adversarial hammering)", 0, 300'000);
    contended_regime("~0.8us dependent work between ops (ready-queue spacing)", 1024, 100'000);
    return 0;
}
