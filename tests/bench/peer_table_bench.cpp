// PeerTable lookup against the obvious baseline: a sharded std::shared_mutex +
// std::unordered_map, which is what most servers use for a concurrent
// address->entry map. Lookup is the per-packet hot path, so this is the bench
// that most has to earn the hand-built table's complexity. Measures single-
// thread ns/op, read-throughput scaling, and — the design's actual claim —
// read latency while a writer churns registrations. The seqlock's promise is
// that readers store nothing shared and writers do not stall them; the read
// tail under churn is where that promise is kept or broken.
//
// Note the two do not return the same thing: the baseline hands back a bare
// slot index under a shared lock, while GetPeer returns a read-locked PeerHandle
// with the key verified against the peer itself. Ours does strictly more work
// per lookup and is still expected to scale better, because its readers store
// nothing shared.
#include <flux/peer/peer_table.h>
#include <flux/peer/peer_handle.h>
#include <flux/address.h>

#include "bench_harness.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <shared_mutex>
#include <thread>
#include <unordered_map>
#include <vector>

using bcp::flux::Address;
using bcp::flux::PeerHandle;
using bcp::flux::PeerTable;

// The baseline: N shards, each a shared_mutex over an unordered_map keyed by the
// address hash. shared_mutex is non-movable, so the shards are constructed in
// place.
struct ShardedMap
{
    struct Shard
    {
        std::shared_mutex                      mutex;
        std::unordered_map<uint64_t, uint32_t> map;
    };
    std::vector<Shard> shards;
    size_t             count = 0;

    void Init(size_t shardCount)
    {
        count  = shardCount;
        shards = std::vector<Shard>(shardCount);
    }
    void Insert(uint64_t key, uint32_t slot)
    {
        Shard& shard = shards[key % count];
        std::unique_lock<std::shared_mutex> guard(shard.mutex);
        shard.map[key] = slot;
    }
    void Erase(uint64_t key)
    {
        Shard& shard = shards[key % count];
        std::unique_lock<std::shared_mutex> guard(shard.mutex);
        shard.map.erase(key);
    }
    uint32_t Lookup(uint64_t key)
    {
        Shard& shard = shards[key % count];
        std::shared_lock<std::shared_mutex> guard(shard.mutex);
        auto it = shard.map.find(key);
        return it == shard.map.end() ? UINT32_MAX : it->second;
    }
};

// Scatter lookups across the whole address set so the access pattern is not
// cache-friendly.
static constexpr uint64_t SCATTER = 2654435761ull;

// Runs `perThread` lookups on each of `threads` threads and returns the
// wall-clock seconds. lookupOne(index) performs one lookup and returns a value
// to accumulate, so the shared sink is touched once per thread, not per lookup.
template <typename LookupOne>
static double run_reads(int threads, uint64_t perThread, LookupOne lookupOne)
{
    auto worker = [&](int threadId)
    {
        uint64_t counter = static_cast<uint64_t>(threadId) * 0x9E3779B1ull;
        uint64_t local   = 0;
        for (uint64_t i = 0; i < perThread; ++i) local += lookupOne(counter++);
        bench::sink += local;
    };

    auto start = std::chrono::steady_clock::now();
    std::vector<std::thread> workers;
    for (int i = 0; i < threads; ++i) workers.emplace_back(worker, i);
    for (auto& t : workers) t.join();
    auto end = std::chrono::steady_clock::now();

    return std::chrono::duration<double>(end - start).count();
}

// Runs `perThread` lookups on each of `threads` threads, timing every one.
// The clock read adds ~40ns to each sample; both contenders pay it equally,
// and the section exists for the shape of the tail, not the mean.
template <typename LookupOne>
static std::vector<uint32_t> run_read_latency(int threads, uint64_t perThread, LookupOne lookupOne)
{
    std::vector<std::vector<uint32_t>> perThreadSamples;
    perThreadSamples.resize(static_cast<size_t>(threads));

    auto worker = [&](int threadId)
    {
        auto& samples = perThreadSamples[static_cast<size_t>(threadId)];
        samples.reserve(perThread);
        uint64_t counter = static_cast<uint64_t>(threadId) * 0x9E3779B1ull;
        uint64_t local   = 0;
        for (uint64_t i = 0; i < perThread; ++i)
        {
            auto before = std::chrono::steady_clock::now();
            local += lookupOne(counter++);
            auto after = std::chrono::steady_clock::now();
            samples.push_back(static_cast<uint32_t>(
                std::chrono::duration_cast<std::chrono::nanoseconds>(after - before).count()));
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

int main()
{
    constexpr uint32_t PEERS      = 8192;
    constexpr uint32_t CAPACITY   = 16384;   // ~50% load, well under the table's cap
    constexpr uint16_t BASE_PORT  = 1024;
    constexpr uint64_t ITERATIONS = 5'000'000;

    std::printf("PeerTable vs sharded std::shared_mutex + std::unordered_map\n");

    PeerTable table;
    if (table.Init(CAPACITY) != bcp::common::Error::Ok)
    {
        std::printf("  table init failed\n");
        return 0;
    }

    ShardedMap baseline;
    baseline.Init(64);

    std::vector<Address> addresses;
    addresses.reserve(PEERS);
    for (uint32_t i = 0; i < PEERS; ++i)
    {
        Address addr = Address::From("::1", static_cast<uint16_t>(BASE_PORT + i)).Take();
        uint32_t slot = 0;
        if (table.RegisterPeer(addr, nullptr, slot) != bcp::common::Error::Ok) break;
        baseline.Insert(addr.hash(), slot);
        addresses.push_back(addr);
    }
    uint32_t n = static_cast<uint32_t>(addresses.size());
    std::printf("  populated %u peers\n", n);

    auto lookupOurs = [&](uint64_t index) -> uint64_t
    {
        const Address& addr = addresses[(index * SCATTER) % n];
        PeerHandle peer = table.GetPeer(addr);
        return peer.Failed() ? 0u : 1u;
    };
    auto lookupBaseline = [&](uint64_t index) -> uint64_t
    {
        const Address& addr = addresses[(index * SCATTER) % n];
        return baseline.Lookup(addr.hash());
    };

    uint64_t single = 0;
    double oursNs = bench::ns_per_op(ITERATIONS, 100000, [&] { bench::sink += lookupOurs(single++); });
    single = 0;
    double baselineNs = bench::ns_per_op(ITERATIONS, 100000, [&] { bench::sink += lookupBaseline(single++); });
    bench::compare("lookup", oursNs, baselineNs);

    constexpr uint64_t PER = 2'000'000;
    for (int threads : {1, 2, 4, 8, 16})
    {
        double oursSeconds = run_reads(threads, PER, lookupOurs);
        bench::throughput("peer_table", PER * threads, oursSeconds, threads);

        double baselineSeconds = run_reads(threads, PER, lookupBaseline);
        bench::throughput("sharded_map", PER * threads, baselineSeconds, threads);
    }

    // Read latency with and without a churning writer: 4 readers over the
    // stable peers while one writer registers and removes a disjoint address
    // range flat out. Displacement and backward-shift move index entries, so
    // this is exactly the path that makes seqlock readers retry.
    constexpr uint32_t CHURN       = 64;
    constexpr uint16_t CHURN_PORT  = 30000;
    constexpr uint64_t LAT_PER     = 500'000;
    constexpr int      LAT_READERS = 4;

    std::vector<Address> churnAddrs;
    churnAddrs.reserve(CHURN);
    for (uint32_t i = 0; i < CHURN; ++i)
        churnAddrs.push_back(Address::From("::1", static_cast<uint16_t>(CHURN_PORT + i)).Take());

    auto readTail = [&](const char* label, bool withChurn, auto&& lookupOne, auto&& churnOnce)
    {
        std::atomic<bool> stop{false};
        std::thread writer;
        if (withChurn)
            writer = std::thread([&]
            {
                uint64_t i = 0;
                while (!stop.load(std::memory_order_relaxed)) { churnOnce(i); ++i; }
            });

        std::vector<uint32_t> samples = run_read_latency(LAT_READERS, LAT_PER, lookupOne);
        bench::latency(label, samples);

        if (withChurn)
        {
            stop.store(true, std::memory_order_relaxed);
            writer.join();
        }
    };

    auto churnOurs = [&](uint64_t i)
    {
        const Address& addr = churnAddrs[i % CHURN];
        uint32_t slot = 0;
        (void)table.RegisterPeer(addr, nullptr, slot);
        (void)table.RemovePeer(addr);
    };
    auto churnBaseline = [&](uint64_t i)
    {
        const Address& addr = churnAddrs[i % CHURN];
        baseline.Insert(addr.hash(), 1);
        baseline.Erase(addr.hash());
    };

    std::printf("  --- read latency, 4 readers (per-sample clock adds ~40ns to both) ---\n");
    readTail("peer_table, quiet",   false, lookupOurs,     churnOurs);
    readTail("peer_table, churn",   true,  lookupOurs,     churnOurs);
    readTail("sharded_map, quiet",  false, lookupBaseline, churnBaseline);
    readTail("sharded_map, churn",  true,  lookupBaseline, churnBaseline);

    return 0;
}
