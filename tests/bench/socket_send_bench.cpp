// Socket send-path cost through an established Flux session, against two
// reference points: the bare OS sendto() syscall, the floor any UDP transport
// pays, and Flux's own unsecured send, same framing without the AEAD seal. So
// the numbers separate what framing costs from what encryption costs.
//
// Method matters more than usual here. A drainer thread keeps the receiver
// read for the whole run, and the three variants are sampled in small
// interleaved blocks rather than one after another: an undrained loopback
// flood degrades the host's entire network path on some systems (macOS,
// visibly), and sequential windows would then each measure a different
// machine. Every send is timed individually, so each variant reports its
// latency distribution, and the framing/seal deltas are taken at the median,
// which resists tail noise.
#include <flux/wire/packet_builder.h>

#include "flux_net.h"
#include "bench_harness.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <numeric>
#include <thread>
#include <vector>

#ifdef _WIN32
    using RawSocket = SOCKET;
    static void CloseRaw(RawSocket s) { closesocket(s); }
#else
    #include <unistd.h>
    using RawSocket = int;
    static void CloseRaw(RawSocket s) { ::close(s); }
#endif

namespace flux = bcp::flux;
namespace common = bcp::common;

static uint32_t percentile_of(std::vector<uint32_t>& sorted, double p)
{
    return sorted[static_cast<size_t>(static_cast<double>(sorted.size() - 1) * p)];
}

int main()
{
    constexpr uint16_t SENDER_PORT   = 9601;
    constexpr uint16_t RECEIVER_PORT = 9602;
    constexpr int      ROUNDS        = 150;
    constexpr int      BLOCK         = 200;   // sends per variant per round

    std::printf("Flux send path vs bare sendto() and vs unsecured send\n");
    std::printf("  (receiver drained throughout; variants interleaved per round)\n");

    flux::Socket sender, receiver;
    common::Error senderErr = sender.Init({ .type = flux_net::BACKEND, .port = SENDER_PORT,
                                            .maxPeers = 64, .pendingPacketCount = 256 });
    common::Error receiverErr = receiver.Init({ .type = flux_net::BACKEND, .port = RECEIVER_PORT,
                                                .maxPeers = 64, .pendingPacketCount = 256 });
    if (senderErr != common::Error::Ok || receiverErr != common::Error::Ok)
    {
        std::printf("  socket init failed\n");
        return 0;
    }

    const flux::Address receiverAddr = flux_net::Loopback(RECEIVER_PORT);
    const flux::Address senderAddr   = flux_net::Loopback(SENDER_PORT);

    if (sender.Connect(receiverAddr) != common::Error::Ok ||
        !flux_net::PumpUntilEstablished(sender, senderAddr, receiver, receiverAddr))
    {
        std::printf("  handshake did not establish\n");
        return 0;
    }

    // Keeps the receiver's kernel buffer empty for the whole run. Raw packets
    // aim at the same port: Flux reads them out of the socket and drops them
    // at the inbound gate, which is exactly the drain that matters.
    std::atomic<bool> stopDrainer{false};
    std::thread drainer([&]
    {
        flux::PacketSlotHandle drained[64];
        while (!stopDrainer.load(std::memory_order_relaxed))
        {
            receiver.Poll(drained, 64);
            receiver.Update();
            std::this_thread::yield();
        }
    });

    RawSocket raw = ::socket(AF_INET6, SOCK_DGRAM, 0);
    const sockaddr_storage& target = receiverAddr;

    for (uint16_t size : {64, 1024})
    {
        std::vector<uint8_t> payload(size, 0xAB);

        std::vector<uint32_t> secureNs, unsecuredNs, rawNs;
        secureNs.reserve(ROUNDS * BLOCK);
        unsecuredNs.reserve(ROUNDS * BLOCK);
        rawNs.reserve(ROUNDS * BLOCK);
        uint64_t sendErrors = 0;

        auto timedSecure = [&]
        {
            auto before = std::chrono::steady_clock::now();
            common::Error sent = sender.BuildPacket().NoFlow()
                .PutBytes(payload.data(), payload.size()).Send(receiverAddr);
            auto after = std::chrono::steady_clock::now();
            if (sent != common::Error::Ok) ++sendErrors;
            secureNs.push_back(static_cast<uint32_t>(
                std::chrono::duration_cast<std::chrono::nanoseconds>(after - before).count()));
        };
        auto timedUnsecured = [&]
        {
            auto before = std::chrono::steady_clock::now();
            common::Error sent = sender.BuildPacket().Unsecured().NoFlow()
                .PutBytes(payload.data(), payload.size()).Send(receiverAddr);
            auto after = std::chrono::steady_clock::now();
            if (sent != common::Error::Ok) ++sendErrors;
            unsecuredNs.push_back(static_cast<uint32_t>(
                std::chrono::duration_cast<std::chrono::nanoseconds>(after - before).count()));
        };
        auto timedRaw = [&]
        {
            auto before = std::chrono::steady_clock::now();
            auto sent = ::sendto(raw, reinterpret_cast<const char*>(payload.data()),
                                 payload.size(), 0,
                                 reinterpret_cast<const sockaddr*>(&target),
                                 sizeof(sockaddr_in6));
            auto after = std::chrono::steady_clock::now();
            if (sent < 0) ++sendErrors;
            rawNs.push_back(static_cast<uint32_t>(
                std::chrono::duration_cast<std::chrono::nanoseconds>(after - before).count()));
        };

        // One untimed warm round, then the interleaved measurement.
        for (int i = 0; i < BLOCK; ++i) { timedSecure(); timedUnsecured(); timedRaw(); }
        secureNs.clear(); unsecuredNs.clear(); rawNs.clear(); sendErrors = 0;

        for (int round = 0; round < ROUNDS; ++round)
        {
            for (int i = 0; i < BLOCK; ++i) timedSecure();
            for (int i = 0; i < BLOCK; ++i) timedUnsecured();
            for (int i = 0; i < BLOCK; ++i) timedRaw();
        }

        std::printf("  --- %u-byte payload ---\n", size);
        auto mean = [](const std::vector<uint32_t>& ns)
        {
            return static_cast<double>(std::accumulate(ns.begin(), ns.end(), uint64_t{0}))
                 / static_cast<double>(ns.size());
        };
        double secureMean = mean(secureNs), unsecuredMean = mean(unsecuredNs), rawMean = mean(rawNs);

        bench::report("flux secure send", secureMean);
        bench::latency("  ", secureNs);
        bench::report("flux unsecured send", unsecuredMean);
        bench::latency("  ", unsecuredNs);
        bench::report("raw udp sendto", rawMean);
        bench::latency("  ", rawNs);

        // latency() sorted the vectors, so medians are direct reads.
        const uint32_t secureP50    = percentile_of(secureNs, 0.50);
        const uint32_t unsecuredP50 = percentile_of(unsecuredNs, 0.50);
        const uint32_t rawP50       = percentile_of(rawNs, 0.50);
        std::printf("    framing adds %d ns and the seal adds %d ns, at the median\n",
                    static_cast<int>(unsecuredP50) - static_cast<int>(rawP50),
                    static_cast<int>(secureP50) - static_cast<int>(unsecuredP50));
        if (sendErrors) std::printf("    send errors: %llu\n",
                                    static_cast<unsigned long long>(sendErrors));
    }

    stopDrainer.store(true, std::memory_order_relaxed);
    drainer.join();
    if (raw != static_cast<RawSocket>(-1)) CloseRaw(raw);
    return 0;
}
