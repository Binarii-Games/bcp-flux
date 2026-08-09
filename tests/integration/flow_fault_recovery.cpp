// Ten damaged links, one contract: every transfer completes, intact and in
// order, given a client that retries the way a real one would.
//
// Loopback never loses anything, so an ordinary run exercises none of the
// recovery machinery. Each case here puts the fault-injecting kernel under the
// client and gives it a different mixture of loss, burst loss, duplication,
// reordering, corruption, handshake loss and latency, all derived from a fixed
// seed. Fixed rather than drawn from the clock, so a failure in CI replays
// byte for byte on the machine that has to diagnose it, and varied rather than
// ten copies of one worst case, because the interesting failures live in the
// combinations.
//
// The client retries the way an application has to: when the transport reports
// the target has given up, it reopens the flow and resends from the first
// packet the receiver has not delivered. It reopens under THE SAME FLOW ID,
// which is the demanding path and the one worth guarding. An id closed and
// reopened numbers its packets from one again while the receiver still holds
// the old association, so every piece of state keyed on that id has to know
// which generation is speaking: the data packets, the acks that answer them,
// and the refusals. When any of those forgets, the symptom is not an error, it
// is silence or wrong bytes, which is why the ordering check below matters as
// much as the completion one.
//
// A run is allowed MAX_RETRIES attempts and a wall budget sized from them. One
// attempt can spend HANDSHAKE_MAX_ATTEMPTS handshakes at HANDSHAKE_RETRY_DEFAULT
// apart before the transport declares the target unreachable, so the budget is
// that cost times the retry count plus room for the transfer itself.
#include "flux_net.h"

#include <flux/flow/flow_handle.h>
#include <flux/internal/constants.h>
#include <flux/socket/packet_slot.h>
#include <flux/socket/platform/faulty_socket.h>
#include <flux/wire/packet_builder.h>

#include "harness.h"

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <thread>

namespace flux   = bcp::flux;
namespace common = bcp::common;

using flux::platform::FaultySocket;
using flux_net::Loopback;

namespace
{
    constexpr int      PACKET_COUNT = 40;
    constexpr int      PAYLOAD_SIZE = 500;
    constexpr uint16_t FLOW_ID      = 11;
    constexpr int      MAX_RETRIES  = 8;

    /** One attempt can burn a full handshake budget before the transport calls
        the target unreachable, so the wall budget is that cost per retry with
        room on top for the transfer. */
    constexpr int64_t RUN_BUDGET_MILLIS =
        static_cast<int64_t>(MAX_RETRIES + 1)
            * (flux::internal::HANDSHAKE_MAX_ATTEMPTS
               * flux::internal::HANDSHAKE_RETRY_DEFAULT / 1000)
        + 2000;

    /** Ten links, each a different way of being bad. Chosen to span the range
        rather than sample one point of it: the first is barely lossy, the last
        loses a quarter of everything in bursts of four while corrupting one
        packet in eight and dropping a quarter of the handshakes. */
    struct Link
    {
        uint64_t seed;
        uint8_t  loss, burst, duplicate, reorder, reorderDepth, corrupt, handshakeLoss;
        uint32_t latencyMicros, jitterMicros;
    };

    constexpr Link LINKS[] = {
        { 0xA1000001ull,  5, 1,  0,  0, 1,  0,  0,    0,    0 },
        { 0xB2000002ull, 10, 1,  5,  0, 1,  0,  0,  200,  100 },
        { 0xC3000003ull,  8, 1,  0, 20, 4,  0,  0,  150,  600 },
        { 0xD4000004ull, 12, 3,  0,  0, 1,  0,  0,  300,  200 },
        { 0xE5000005ull,  6, 1, 15,  0, 1,  8,  0,  100,  300 },
        { 0xF6000006ull, 15, 2, 10, 15, 2,  0, 10,  250,  500 },
        { 0x17000007ull, 20, 4,  0, 10, 3,  5,  0,  400,  700 },
        { 0x28000008ull, 10, 1,  0,  0, 1, 12, 20,  100,  200 },
        { 0x39000009ull, 18, 2, 12, 22, 4,  6, 15,  300,  900 },
        { 0x4A00000Aull, 25, 2, 15, 20, 4, 12, 25,  300,  900 },
    };

    // The last link is the ceiling for the contract above, and it is set by
    // arithmetic rather than by what happened to pass. Burst loss multiplies
    // the base rate, because one roll discards a whole run: at 25 percent with
    // bursts of four that is around 57 percent of everything, and a four
    // message handshake then completes about six times in a thousand attempts.
    // The budget here allows sixty four, so the exchange fails more often than
    // not no matter how correct the code is. Bursts of two keep the link
    // brutal and keep the contract reachable.

    /** Every run reopens the flow once partway through, on top of whatever
        reopening the faults force. Waiting for a link bad enough to make the
        transport give up leaves most of these cases never exercising a
        generation change at all, and the generation logic is the part with
        nowhere to report a mistake: a stale ack resolves packets that were
        never delivered, the sender stops resending them, and the transfer stops
        with the flow still reporting itself healthy. Reopening on purpose puts
        every link through that window with acks in flight. */
    constexpr int REOPEN_AFTER = PACKET_COUNT / 3;

    struct Outcome
    {
        int  delivered  = 0;
        int  retries    = 0;   ///< reopens the faults forced
        bool reopened   = false;   ///< the deliberate one happened
        bool ordered    = true;   ///< false the moment a packet arrives out of turn
        bool setupFault = false;  ///< the harness itself failed, not the transport

        /** The injector's own account of the damage it did. Loopback loses
            nothing, so without these the whole file passes over a clean link
            and proves only that an undamaged transfer works. Read from both
            kernels because the damaged return path is load-bearing here: the
            acknowledgements are attacked as well as the data. */
        uint64_t forwardDropped = 0;
        uint64_t returnDropped  = 0;
        uint64_t corrupted      = 0;
    };

    FaultySocket::Profile ProfileFor(const Link& link, uint64_t seed)
    {
        FaultySocket::Profile profile{};
        profile.seed                 = seed;
        profile.applyTo              = FaultySocket::Direction::Send;
        profile.lossPercent          = link.loss;
        profile.burstLoss            = link.burst;
        profile.duplicatePercent     = link.duplicate;
        profile.reorderPercent       = link.reorder;
        profile.reorderDepth         = link.reorderDepth;
        profile.corruptPercent       = link.corrupt;
        profile.handshakeLossPercent = link.handshakeLoss;
        profile.latencyMicros        = link.latencyMicros;
        profile.jitterMicros         = link.jitterMicros;
        return profile;
    }

    Outcome RunOne(const Link& link, uint16_t port)
    {
        Outcome outcome;

        flux::Socket::Config config{};
        config.type               = flux::Socket::BackendType::FAULTY;
        config.maxPeers           = 8;
        config.pendingPacketCount = 64;
        config.flows.outCount     = 8;
        config.flows.inCount      = 8;
        config.flows.flowCount    = 64;

        flux::Socket client, server;
        config.port = port;
        if (client.Init(config) != common::Error::Ok) { outcome.setupFault = true; return outcome; }
        config.port = static_cast<uint16_t>(port + 1);
        if (server.Init(config) != common::Error::Ok) { outcome.setupFault = true; return outcome; }

        // Both directions are damaged, and the return path matters as much as
        // the forward one. An ack that arrives late, twice or out of order is
        // the only way an ack for a closed generation can still be in the air
        // when its id reopens, so a clean return path would hide exactly the
        // failure this case exists to catch. The two are seeded apart so the
        // directions do not lose the same packets in step.
        FaultySocket* clientKernel = FaultySocket::ForPort(port);
        FaultySocket* serverKernel = FaultySocket::ForPort(static_cast<uint16_t>(port + 1));
        if (!clientKernel || !serverKernel) { outcome.setupFault = true; return outcome; }

        clientKernel->SetProfile(ProfileFor(link, link.seed));
        serverKernel->SetProfile(ProfileFor(link, link.seed ^ 0x5DEECE66Dull));

        const flux::Address serverAddr = Loopback(static_cast<uint16_t>(port + 1));

        flux::FlowHandle flow = client.OpenFlow(FLOW_ID, flux::FlowMode::RELIABLE_ORDERED);
        if (flow.Failed()) { outcome.setupFault = true; return outcome; }

        uint8_t                payload[PAYLOAD_SIZE]{};
        flux::PacketSlotHandle sink[64];
        int  sent     = 0;
        bool hadAssoc = false;   // CLOSED also means "no association yet"

        const auto start    = std::chrono::steady_clock::now();
        const auto deadline = start + std::chrono::milliseconds(RUN_BUDGET_MILLIS);

        while (outcome.delivered < PACKET_COUNT)
        {
            if (std::chrono::steady_clock::now() > deadline) break;

            const flux::FlowLifecycle state = client.GetFlowState(flow, serverAddr);
            if (state == flux::FlowLifecycle::OPEN) hadAssoc = true;

            // The transport has given up on this target. An application's
            // answer is to open the flow again and resend from the first packet
            // that was never delivered.
            if (state == flux::FlowLifecycle::FAILED
             || (hadAssoc && state == flux::FlowLifecycle::CLOSED))
            {
                if (outcome.retries >= MAX_RETRIES) break;
                ++outcome.retries;

                (void)client.CloseFlow(flow);
                flow = client.OpenFlow(FLOW_ID, flux::FlowMode::RELIABLE_ORDERED);
                if (flow.Failed()) { outcome.setupFault = true; break; }

                sent     = outcome.delivered;
                hadAssoc = false;
                std::this_thread::sleep_for(std::chrono::milliseconds(2));
                continue;
            }

            // The deliberate one, under the same id, once the receiver has
            // taken a wide enough run of sequences to owe a substantial ack for
            // them. That ack is the hazard: it names sequences the old
            // generation delivered, and the new generation is about to number
            // its own packets over the same ones.
            if (!outcome.reopened && outcome.delivered >= REOPEN_AFTER)
            {
                outcome.reopened = true;

                (void)client.CloseFlow(flow);
                flow = client.OpenFlow(FLOW_ID, flux::FlowMode::RELIABLE_ORDERED);
                if (flow.Failed()) { outcome.setupFault = true; break; }

                sent     = outcome.delivered;
                hadAssoc = false;
                continue;
            }

            // Nothing past the reopen point goes out until the reopen has
            // happened. A fast link otherwise delivers the whole transfer in
            // one batch and leaves the loop before the generation ever changes,
            // which is precisely the case that needs it most.
            const int sendCeiling = outcome.reopened ? PACKET_COUNT : REOPEN_AFTER;
            if (sent < sendCeiling)
            {
                payload[0] = static_cast<uint8_t>(sent);
                payload[1] = static_cast<uint8_t>(sent >> 8);
                if (client.BuildPacket().WithFlow(flow)
                        .PutBytes(payload, sizeof(payload)).Send(serverAddr)
                    == common::Error::Ok)
                    ++sent;
            }

            client.Flush();
            client.Update();
            client.Poll(sink, 64);
            server.Flush();
            server.Update();

            flux::PollCursor cursor = server.Poll(sink, 64);
            while (cursor.Next())
            {
                const flux::PacketSlot* packet = cursor.Packet().Read();
                if (!packet) continue;

                const uint8_t* body = cursor.Message().Content();
                const int index = static_cast<int>(body[0])
                                | static_cast<int>(body[1]) << 8;

                // A resend after a retry legitimately repeats what was already
                // delivered, so a repeat is fine and a skip is not.
                if (index == outcome.delivered) ++outcome.delivered;
                else if (index > outcome.delivered) outcome.ordered = false;
            }

            std::this_thread::sleep_for(std::chrono::microseconds(150));
        }

        // Handles borrow slots from the socket's pools, so every one still held
        // goes back before the sockets do.
        for (flux::PacketSlotHandle& handle : sink)
            handle = flux::PacketSlotHandle::Invalid();

        // Before Shutdown, which destroys the kernel these point into.
        const FaultySocket::Stats forward = clientKernel->GetStats();
        const FaultySocket::Stats ret     = serverKernel->GetStats();
        outcome.forwardDropped = forward.dropped;
        outcome.returnDropped  = ret.dropped;
        outcome.corrupted      = forward.corrupted + ret.corrupted;

        client.Shutdown();
        server.Shutdown();
        return outcome;
    }
}

int main()
{
    uint16_t port = 21600;
    uint64_t totalDamage = 0;

    for (const Link& link : LINKS)
    {
        const Outcome outcome = RunOne(link, port);
        port = static_cast<uint16_t>(port + 2);

        std::printf("seed 0x%08llX loss=%2u%% burst=%u dup=%2u%% reorder=%2u%%"
                    " corrupt=%2u%% hs-loss=%2u%%  ->  %2d/%d delivered,"
                    " %d forced retries, reopened=%d\n",
                    static_cast<unsigned long long>(link.seed),
                    link.loss, link.burst, link.duplicate, link.reorder,
                    link.corrupt, link.handshakeLoss,
                    outcome.delivered, PACKET_COUNT, outcome.retries,
                    outcome.reopened ? 1 : 0);
        std::printf("             injector: dropped %llu out / %llu back, corrupted %llu\n",
                    (unsigned long long)outcome.forwardDropped,
                    (unsigned long long)outcome.returnDropped,
                    (unsigned long long)outcome.corrupted);

        CHECK(!outcome.setupFault);
        CHECK(outcome.reopened);
        CHECK(outcome.ordered);
        CHECK(outcome.delivered == PACKET_COUNT);

        // The control. Loopback is perfect, so a green run above means
        // nothing unless the damage this link describes actually happened.
        // Without this the whole file passes with fault injection switched
        // off, proving only that an undamaged transfer works.
        //
        // Totalled rather than split by direction, because the split is not
        // guaranteed by the setup: the mildest link injects five percent with
        // no added latency and its return traffic is small enough that zero
        // acknowledgements are dropped, reproducibly. Asserting per direction
        // would be asserting something these links do not promise. The total
        // still catches the failure this exists for, since an injector that
        // stopped applying would read zero on every link.
        const uint64_t damage = outcome.forwardDropped
                              + outcome.returnDropped + outcome.corrupted;
        CHECK(damage > 0);
        totalDamage += damage;

        // Corruption is the one fault with no other symptom: a flipped bit
        // fails the seal and the packet vanishes, so if this stopped working
        // the transfer would simply get easier.
        if (link.corrupt > 0) CHECK(outcome.corrupted > 0);
    }

    // An injector that fired a handful of times across ten links would pass
    // every per-link check above while exercising almost nothing. Measured
    // total across these seeds is around three hundred and fifty.
    CHECK(totalDamage > 100);

    return test::report();
}
