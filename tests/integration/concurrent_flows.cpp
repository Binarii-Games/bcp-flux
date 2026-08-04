// Data integrity when everything runs at once: several senders, several
// flushers, several updaters, all on live sockets at the same time.
//
// Built to find races, not to be fast. The threads deliberately contend on the
// same sockets and, in the second phase, on the same flow, because that is the
// path batching added shared state to: a send packs into its flow's open batch,
// so two threads sending on one flow write the same buffer under the same lock.
//
// What it asserts:
//   every message arrives, exactly once, with its bytes intact
//   a flow written by ONE thread is delivered in the order that thread sent
//   a flow written by SEVERAL threads delivers all of them, in some order,
//     because concurrent senders have no order between them to preserve
//
// The harness counts checks in plain ints, so nothing here calls CHECK from a
// thread. Threads record into storage they alone own and the main thread judges
// it after joining.
//
// Worth running under TSan, which is the sanitizer that can see what this is
// built to provoke.
#include <flux/socket/socket.h>
#include <flux/address.h>
#include <flux/wire/packet_builder.h>
#include <flux/socket/packet_slot.h>
#include <flux/flow/flow_handle.h>
#include <flux/socket/platform/faulty_socket.h>

#include "flux_net.h"
#include "harness.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <thread>
#include <vector>

namespace flux   = bcp::flux;
namespace common = bcp::common;

namespace
{
    constexpr uint16_t CLIENT_PORT = 22800;
    constexpr uint16_t SERVER_PORT = 22801;

    constexpr uint32_t SENDER_THREADS   = 6;
    constexpr uint32_t PER_SENDER       = 80;
    constexpr uint32_t FILL_BYTES       = 50;    // 6 of header, so 56 on the wire
    /** Per phase. Generous because a sanitized build runs several times
        slower and this must finish there too, and it is only ever reached when
        something has actually stalled. */
    constexpr auto     RUN_LIMIT        = std::chrono::seconds(45);

    /** Every byte derived from the pair it belongs to, so a payload that
        arrives under the wrong header, or half rewritten by a racing sender,
        does not match. */
    uint8_t FillByte(uint16_t flowId, uint32_t index, uint32_t at)
    {
        return static_cast<uint8_t>(flowId * 31u + index * 7u + at);
    }

    common::Error Init(flux::Socket& socket, uint16_t port, bool faulty)
    {
        flux::Socket::Config config{};
        // A healthy link first, so a failure there is the machinery rather than
        // the network. Then the same run over a link that loses, duplicates and
        // reorders, where reliable ordered still owes exactly the same answers.
        config.type = faulty ? flux::Socket::BackendType::FAULTY : flux_net::BACKEND;
        config.port = port;
        config.maxPeers = 8;
        config.pendingPacketCount = 256;
        config.flows.outCount = 16;
        config.flows.inCount  = 16;
        config.flows.maxOutPerPeer = 16;
        config.flows.maxInPerPeer  = 16;
        config.flows.stagingCount     = 2048;
        config.flows.reliableWaitCount = 256;
        return socket.Init(config);
    }

    /** One delivered message, as the poller read it off the wire. */
    struct Received
    {
        uint16_t flowId;
        uint32_t index;
        bool     fillOk;
    };

    /** Sends its share and keeps sending until it all goes. A refusal means the
        window or the budget is full, which under this much contention is the
        normal answer rather than a failure, so it waits and asks again. */
    void SendRange(flux::Socket& socket, const flux::FlowHandle& flow, uint16_t flowId,
                   uint32_t first, uint32_t count, const flux::Address& to,
                   std::atomic<bool>& stop, std::atomic<uint32_t>& refusals,
                   std::atomic<uint32_t>& accepted)
    {
        uint8_t fill[FILL_BYTES];
        for (uint32_t n = 0; n < count && !stop.load(std::memory_order_relaxed); ++n)
        {
            const uint32_t index = first + n;
            for (uint32_t i = 0; i < FILL_BYTES; ++i)
                fill[i] = FillByte(flowId, index, i);

            for (;;)
            {
                if (stop.load(std::memory_order_relaxed)) return;
                const common::Error sent = socket.BuildPacket()
                    .WithFlow(flow)
                    .PutU16(flowId)
                    .PutU32(index)
                    .PutBytes(fill, FILL_BYTES)
                    .Send(to);
                if (sent == common::Error::Ok)
                {
                    accepted.fetch_add(1, std::memory_order_relaxed);
                    break;
                }
                refusals.fetch_add(1, std::memory_order_relaxed);
                std::this_thread::sleep_for(std::chrono::microseconds(200));
            }
        }
    }

    /** Reads everything the server delivers into storage it alone writes, so
        the main thread can judge it once the threads are gone. */
    void PollInto(flux::Socket& socket, std::vector<Received>& out,
                  std::atomic<bool>& stop, std::atomic<uint32_t>& collected)
    {
        flux::PacketSlotHandle inbox[64];
        while (!stop.load(std::memory_order_relaxed))
        {
            flux::PollCursor cursor = socket.Poll(inbox, 64);
            while (cursor.Next())
            {
                const flux::PacketSlot* packet = cursor.Packet().Read();
                if (!packet) continue;

                const uint8_t* body   = cursor.Message().Content();
                const size_t   length = cursor.Message().ContentLength();
                if (body && length == 6 + FILL_BYTES)
                {
                    Received got{};
                    got.flowId = static_cast<uint16_t>(body[0] | (body[1] << 8));
                    got.index  = static_cast<uint32_t>(body[2])
                               | static_cast<uint32_t>(body[3]) << 8
                               | static_cast<uint32_t>(body[4]) << 16
                               | static_cast<uint32_t>(body[5]) << 24;
                    got.fillOk = true;
                    for (uint32_t k = 0; k < FILL_BYTES; ++k)
                        if (body[6 + k] != FillByte(got.flowId, got.index, k))
                            got.fillOk = false;
                    out.push_back(got);
                    collected.fetch_add(1, std::memory_order_relaxed);
                }
            }
            // Released once the cursor is spent, because a message read out of
            // a batch lives in the slot the cursor is walking.
            for (auto& handle : inbox) handle = flux::PacketSlotHandle::Invalid();
            std::this_thread::sleep_for(std::chrono::microseconds(200));
        }
        for (auto& handle : inbox) handle = flux::PacketSlotHandle::Invalid();
    }

    void DrainAcks(flux::Socket& socket, std::atomic<bool>& stop)
    {
        flux::PacketSlotHandle inbox[64];
        while (!stop.load(std::memory_order_relaxed))
        {
            socket.Poll(inbox, 64);
            for (auto& handle : inbox) handle = flux::PacketSlotHandle::Invalid();
            std::this_thread::sleep_for(std::chrono::microseconds(200));
        }
        for (auto& handle : inbox) handle = flux::PacketSlotHandle::Invalid();
    }

    void FlushLoop(flux::Socket& socket, std::atomic<bool>& stop)
    {
        while (!stop.load(std::memory_order_relaxed))
        {
            socket.Flush();
            std::this_thread::sleep_for(std::chrono::microseconds(300));
        }
        socket.Flush();   // whatever the last round produced
    }

    void UpdateLoop(flux::Socket& socket, std::atomic<bool>& stop)
    {
        while (!stop.load(std::memory_order_relaxed))
        {
            socket.Update();
            std::this_thread::sleep_for(std::chrono::microseconds(300));
        }
    }

    /** Same seed every run, so a failure replays rather than teasing. */
    void SpoilLink(uint16_t port, uint64_t seed, uint8_t loss, uint8_t dup, uint8_t reorder)
    {
        flux::platform::FaultySocket* kernel = flux::platform::FaultySocket::ForPort(port);
        if (!kernel) return;
        flux::platform::FaultySocket::Profile profile{};
        profile.seed             = seed;
        profile.lossPercent      = loss;
        profile.duplicatePercent = dup;
        profile.reorderPercent   = reorder;
        kernel->SetProfile(profile);
    }

    /** The outcome of one phase, judged on the main thread. */
    struct Outcome
    {
        uint32_t elapsedMs   = 0;
        uint32_t delivered   = 0;
        uint32_t duplicates  = 0;
        uint32_t corrupt     = 0;
        uint32_t strayHeader = 0;   ///< a flow or index nobody sent
        uint32_t outOfOrder  = 0;
        uint32_t refusals    = 0;
        uint32_t failedFlows = 0;   ///< gave up retransmitting, so its rest is gone
        bool     completed   = false;
        bool     drainedLate = false;   ///< finished once the senders stopped pushing
    };

    /** Runs one phase and reports it.

        `sharedFlow` puts every sender on one flow, where they have no order
        between them, so ordering is only judged when each sender owns its own.

        `pollerCount` above one means the application is draining from several
        threads, and then delivery order is not observable at all: each poller
        takes whatever the queue hands it, so the order they collectively see is
        the order they happened to run in, not the order the transport
        delivered. Ordering is judged only with a single poller. */
    Outcome RunPhase(bool faulty, bool sharedFlow, uint32_t pollerCount,
                     uint8_t loss, uint8_t dup, uint8_t reorder)
    {
        Outcome outcome{};

        flux::Socket client, server;
        if (Init(client, CLIENT_PORT, faulty) != common::Error::Ok) return outcome;
        if (Init(server, SERVER_PORT, faulty) != common::Error::Ok) return outcome;

        const flux::Address serverAddr = flux_net::Loopback(SERVER_PORT);
        const flux::Address clientAddr = flux_net::Loopback(CLIENT_PORT);
        if (client.Connect(serverAddr) != common::Error::Ok) return outcome;
        if (!flux_net::PumpUntilEstablished(client, clientAddr, server, serverAddr, 600))
            return outcome;

        // Spoiled only after the handshake, so a phase measures the transfer
        // rather than how long the two took to find each other.
        if (faulty)
        {
            SpoilLink(CLIENT_PORT, 0xC0FFEE01ull, loss, dup, reorder);
            SpoilLink(SERVER_PORT, 0xC0FFEE02ull, loss, dup, reorder);
        }

        // Opened up front on one thread, so the phase measures the send path
        // rather than concurrent flow creation.
        std::vector<flux::FlowHandle> flows;
        const uint32_t flowCount = sharedFlow ? 1 : SENDER_THREADS;
        for (uint32_t f = 0; f < flowCount; ++f)
        {
            flux::FlowHandle handle = client.OpenFlow(static_cast<uint16_t>(40 + f),
                                                      flux::FlowMode::RELIABLE_ORDERED);
            if (handle.Failed()) return outcome;
            flows.push_back(std::move(handle));
        }

        const uint32_t total = SENDER_THREADS * PER_SENDER;

        // One bucket per poller, sized before any thread starts and never
        // resized, so each thread writes only the element it owns.
        std::vector<std::vector<Received>> buckets(pollerCount);
        for (auto& bucket : buckets) bucket.reserve(total * 2);
        std::atomic<uint32_t> collected{0};

        std::atomic<bool>     stop{false};
        std::atomic<bool>     stopSenders{false};
        std::atomic<uint32_t> refusals{0};
        std::atomic<uint32_t> accepted{0};

        std::vector<std::thread> threads;
        for (uint32_t p = 0; p < pollerCount; ++p)
            threads.emplace_back(PollInto, std::ref(server), std::ref(buckets[p]),
                                 std::ref(stop), std::ref(collected));
        threads.emplace_back(DrainAcks, std::ref(client), std::ref(stop));
        for (int i = 0; i < 2; ++i)
        {
            threads.emplace_back(FlushLoop,  std::ref(client), std::ref(stop));
            threads.emplace_back(FlushLoop,  std::ref(server), std::ref(stop));
            threads.emplace_back(UpdateLoop, std::ref(client), std::ref(stop));
            threads.emplace_back(UpdateLoop, std::ref(server), std::ref(stop));
        }
        for (uint32_t s = 0; s < SENDER_THREADS; ++s)
        {
            const uint32_t flowIndex = sharedFlow ? 0 : s;
            const uint16_t flowId    = static_cast<uint16_t>(40 + flowIndex);
            // On a shared flow every sender takes its own slice of the index
            // space, so a message still says which thread produced it.
            const uint32_t first = sharedFlow ? s * PER_SENDER : 0;
            threads.emplace_back(SendRange, std::ref(client), std::cref(flows[flowIndex]),
                                 flowId, first, PER_SENDER, std::cref(serverAddr),
                                 std::ref(stopSenders), std::ref(refusals), std::ref(accepted));
        }

        const auto began    = std::chrono::steady_clock::now();
        const auto deadline = began + RUN_LIMIT;
        for (;;)
        {
            if (collected.load(std::memory_order_relaxed) >= total)
            { outcome.completed = true; break; }
            if (std::chrono::steady_clock::now() > deadline) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
        // Senders down first, then a drain with everything else still running.
        // Without it a transfer merely mid-flight at the deadline is
        // indistinguishable from one that has wedged, and those want very
        // different answers.
        stopSenders.store(true, std::memory_order_relaxed);
        const auto drainUntil = std::chrono::steady_clock::now()
                              + std::chrono::seconds(outcome.completed ? 0 : 5);
        while (std::chrono::steady_clock::now() < drainUntil
               && collected.load(std::memory_order_relaxed) < total)
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        outcome.drainedLate = !outcome.completed
                            && collected.load(std::memory_order_relaxed) >= total;

        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        stop.store(true, std::memory_order_relaxed);
        for (std::thread& t : threads) t.join();

        // Judged here, single threaded, with every thread gone. With one poller
        // the single bucket is arrival order; with several it is not, which is
        // why ordering is only judged below when there was one.
        std::vector<Received> received;
        for (const auto& bucket : buckets)
            received.insert(received.end(), bucket.begin(), bucket.end());

        std::vector<std::vector<bool>> seen(flowCount, std::vector<bool>(total, false));
        std::vector<uint32_t> lastIndex(flowCount, 0);
        std::vector<bool>     everSeen(flowCount, false);

        for (const Received& got : received)
        {
            const uint32_t flowIndex = static_cast<uint32_t>(got.flowId) - 40u;
            if (flowIndex >= flowCount || got.index >= total) { ++outcome.strayHeader; continue; }
            if (!got.fillOk) ++outcome.corrupt;
            if (seen[flowIndex][got.index]) { ++outcome.duplicates; continue; }
            seen[flowIndex][got.index] = true;
            ++outcome.delivered;

            // Only meaningful when one thread owns the flow. Concurrent senders
            // have no order between them for the transport to keep.
            if (!sharedFlow && pollerCount == 1)
            {
                if (everSeen[flowIndex] && got.index <= lastIndex[flowIndex]) ++outcome.outOfOrder;
                lastIndex[flowIndex] = got.index;
                everSeen[flowIndex]  = true;
            }
        }

        for (uint32_t f = 0; f < flowCount; ++f)
            if (client.GetFlowState(flows[f], serverAddr) == flux::FlowLifecycle::FAILED)
                ++outcome.failedFlows;

        outcome.refusals  = refusals.load(std::memory_order_relaxed);
        outcome.elapsedMs = static_cast<uint32_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - began).count());
        client.Shutdown();
        server.Shutdown();
        return outcome;
    }
}

int main()
{
    const uint32_t total = SENDER_THREADS * PER_SENDER;

    struct Phase
    {
        const char* name;
        bool     faulty;
        bool     sharedFlow;
        uint32_t pollers;
        uint8_t  loss, dup, reorder;
    };

    // The same three shapes over a healthy link and then a bad one. Reliable
    // ordered owes the same answers on both, so any line that differs between
    // the halves is the network changing an outcome it should not reach.
    const Phase phases[] = {
        // One writer per flow and one reader, the only shape where delivery
        // order is observable, so the only one that judges it.
        { "healthy  own-flow  1 poll", false, false, 1, 0, 0,  0  },
        // Several readers. Order becomes the application's own doing, so only
        // delivery and integrity are judged.
        { "healthy  own-flow  4 poll", false, false, 4, 0, 0,  0  },
        // Every sender on one flow: the contended batch buffer, plus concurrent
        // draining on the other side.
        { "healthy  shared    4 poll", false, true,  4, 0, 0,  0  },

        { "faulty   own-flow  1 poll", true,  false, 1, 8, 5,  10 },
        { "faulty   own-flow  4 poll", true,  false, 4, 8, 5,  10 },
        { "faulty   shared    4 poll", true,  true,  4, 8, 5,  10 },
    };

    for (const Phase& phase : phases)
    {
        const Outcome outcome = RunPhase(phase.faulty, phase.sharedFlow, phase.pollers,
                                         phase.loss, phase.dup, phase.reorder);
        std::printf("%s  delivered=%u/%u dup=%u corrupt=%u stray=%u ooo=%u refused=%u"
                    " %s in %ums\n",
                    phase.name, outcome.delivered, total, outcome.duplicates,
                    outcome.corrupt, outcome.strayHeader, outcome.outOfOrder,
                    outcome.refusals, outcome.completed ? "done" : "RAN OUT",
                    outcome.elapsedMs);
        if (outcome.failedFlows) std::printf("      %u flow(s) gave up\n", outcome.failedFlows);
        if (outcome.drainedLate)
            std::printf("      drained once the senders stopped, so it was behind rather than stuck\n");

        CHECK(outcome.delivered == total);   // reliable means everything arrives
        CHECK(outcome.corrupt == 0);         // and arrives with its bytes intact
        CHECK(outcome.strayHeader == 0);     // and nothing nobody sent
        CHECK(outcome.duplicates == 0);      // the barriers dedupe under contention
        if (!phase.sharedFlow && phase.pollers == 1)
            CHECK(outcome.outOfOrder == 0);  // one writer, one reader, so ordered
    }

    return test::report();
}
