// SlotPool against the obvious baseline for the same job — hand out a lockable
// slot of memory: a std::mutex free-list for the indices plus one
// std::shared_mutex per slot for the guard. Three views:
//   - the full single-thread lease cycle (acquire, write-lock, touch, release);
//   - contended lease cycles with nothing between operations, the adversarial
//     ceiling no real caller produces;
//   - contended lease cycles with ~0.8us of unrelated work between operations,
//     the spacing a packet path actually has.
// Each contended regime runs twice: once untimed-per-op for clean throughput,
// once timing every lease for latency percentiles — per-op clocking costs
// ~40ns, which would distort the hammering throughput if mixed in. Both sides
// pay the same clocking in the latency pass, so the comparison stays fair.
#include <common/collections/slot_pool.h>

#include "bench_harness.h"

#include <chrono>
#include <cstdint>
#include <mutex>
#include <shared_mutex>
#include <thread>
#include <vector>

using bcp::common::collections::SlotPool;

// The baseline: a mutex-guarded free-list of indices, a per-slot shared_mutex
// for the guard, and one backing buffer. Same Acquire/WriteLock/UnlockWrite/
// Release shape as SlotPool so one runner drives both.
struct MutexSlotPool
{
    std::mutex                     freeMutex;
    std::vector<uint32_t>          free;
    std::vector<std::shared_mutex> slotLocks;
    std::vector<uint8_t>           bytes;
    uint32_t                       stride = 0;

    void Init(uint32_t capacity, uint32_t slotSize)
    {
        stride = slotSize;
        free.reserve(capacity);
        for (uint32_t i = 0; i < capacity; ++i) free.push_back(i);
        slotLocks = std::vector<std::shared_mutex>(capacity);
        bytes.resize(static_cast<size_t>(capacity) * slotSize);
    }
    uint32_t Acquire()
    {
        std::lock_guard<std::mutex> guard(freeMutex);
        if (free.empty()) return SlotPool::INVALID;
        uint32_t index = free.back();
        free.pop_back();
        return index;
    }
    void Release(uint32_t index)
    {
        std::lock_guard<std::mutex> guard(freeMutex);
        free.push_back(index);
    }
    uint8_t* WriteLock(uint32_t index)
    {
        slotLocks[index].lock();
        return &bytes[static_cast<size_t>(index) * stride];
    }
    void UnlockWrite(uint32_t index) { slotLocks[index].unlock(); }
};

// One lease cycle: acquire, write-lock, touch a byte, unlock, release. Returns
// the byte touched so callers can accumulate it into the sink themselves (a
// contended runner accumulates per thread, not once per op).
template <typename Pool>
static uint64_t lease_cycle(Pool& pool)
{
    uint32_t index = pool.Acquire();
    if (index == SlotPool::INVALID) return 0;
    uint8_t* slot = pool.WriteLock(index);
    slot[0] = static_cast<uint8_t>(index);
    uint8_t touched = slot[0];
    pool.UnlockWrite(index);
    pool.Release(index);
    return touched;
}

// Unrelated work between operations: a dependent multiply chain the optimizer
// can neither collapse nor overlap with the pool calls. 1024 rounds is roughly
// 0.8us on current hardware — the order of spacing a syscall + seal gives.
static uint64_t dependent_work(uint64_t rounds, uint64_t seed)
{
    uint64_t x = seed;
    for (uint64_t i = 0; i < rounds; ++i)
        x = x * 6364136223846793005ULL + 1442695040888963407ULL;
    return x;
}

template <typename Pool>
static double run_throughput(Pool& pool, int threads, uint64_t perThread, uint64_t workRounds)
{
    auto worker = [&](int threadId)
    {
        uint64_t local = static_cast<uint64_t>(threadId);
        for (uint64_t i = 0; i < perThread; ++i)
        {
            local += lease_cycle(pool);
            if (workRounds) local += dependent_work(workRounds, local);
        }
        bench::sink += local;
    };

    auto start = std::chrono::steady_clock::now();
    std::vector<std::thread> workers;
    for (int i = 0; i < threads; ++i) workers.emplace_back(worker, i);
    for (auto& t : workers) t.join();
    auto end = std::chrono::steady_clock::now();

    return std::chrono::duration<double>(end - start).count();
}

template <typename Pool>
static std::vector<uint32_t> run_latency(Pool& pool, int threads, uint64_t perThread,
                                         uint64_t workRounds)
{
    std::vector<std::vector<uint32_t>> perThreadSamples;
    perThreadSamples.resize(static_cast<size_t>(threads));

    auto worker = [&](int threadId)
    {
        auto& samples = perThreadSamples[static_cast<size_t>(threadId)];
        samples.reserve(perThread);
        uint64_t local = static_cast<uint64_t>(threadId);
        for (uint64_t i = 0; i < perThread; ++i)
        {
            auto before = std::chrono::steady_clock::now();
            local += lease_cycle(pool);
            auto after = std::chrono::steady_clock::now();
            samples.push_back(static_cast<uint32_t>(
                std::chrono::duration_cast<std::chrono::nanoseconds>(after - before).count()));
            if (workRounds) local += dependent_work(workRounds, local);
        }
        bench::sink += local;
    };

    std::vector<std::thread> workers;
    for (int i = 0; i < threads; ++i) workers.emplace_back(worker, i);
    for (auto& t : workers) t.join();

    std::vector<uint32_t> merged;
    for (auto& samples : perThreadSamples)
        merged.insert(merged.end(), samples.begin(), samples.end());
    return merged;
}

static void contended_regime(const char* title, uint64_t workRounds, uint64_t perThread)
{
    constexpr uint32_t CAPACITY  = 4096;
    constexpr uint32_t SLOT_SIZE = 64;

    std::printf("  --- %s ---\n", title);
    for (int threads : {1, 2, 4, 8, 16})
    {
        SlotPool pool;
        (void)pool.Init(CAPACITY, SLOT_SIZE);
        double oursSeconds = run_throughput(pool, threads, perThread, workRounds);
        bench::throughput("slot_pool", perThread * threads, oursSeconds, threads);
        std::vector<uint32_t> oursLat = run_latency(pool, threads, perThread / 2, workRounds);
        bench::latency("  lease latency", oursLat);

        MutexSlotPool baseline;
        baseline.Init(CAPACITY, SLOT_SIZE);
        double baseSeconds = run_throughput(baseline, threads, perThread, workRounds);
        bench::throughput("mutex_slot_pool", perThread * threads, baseSeconds, threads);
        std::vector<uint32_t> baseLat = run_latency(baseline, threads, perThread / 2, workRounds);
        bench::latency("  lease latency", baseLat);
    }
}

static void single_thread_lease_cycle()
{
    constexpr uint32_t CAPACITY   = 4096;
    constexpr uint32_t SLOT_SIZE  = 64;
    constexpr uint64_t ITERATIONS = 3'000'000;

    SlotPool pool;
    (void)pool.Init(CAPACITY, SLOT_SIZE);
    double oursNs = bench::ns_per_op(ITERATIONS, 100000, [&] { bench::sink += lease_cycle(pool); });

    MutexSlotPool baseline;
    baseline.Init(CAPACITY, SLOT_SIZE);
    double baselineNs = bench::ns_per_op(ITERATIONS, 100000, [&] { bench::sink += lease_cycle(baseline); });

    bench::compare("acquire+lock+release", oursNs, baselineNs);
}

int main()
{
    std::printf("SlotPool vs std::mutex free-list + per-slot std::shared_mutex\n");
    single_thread_lease_cycle();
    contended_regime("no work between ops (adversarial hammering)", 0, 400'000);
    contended_regime("~0.8us dependent work between ops (packet-path spacing)", 1024, 120'000);
    return 0;
}
