#pragma once

// A bottleneck link, in process, and one transfer across it.
//
// The model is one queue per direction: arrival, a tail-drop queue bounded in
// bytes, serialisation at the configured rate, propagation delay, delivery. A
// rate limit alone cannot produce bufferbloat, and bufferbloat is what
// separates a controller that finds the bottleneck from one that fills it.
//
// Kept apart from the bench that prints it, so the link and the presentation
// of it stay separable and a second measurement can meet the identical link
// rather than a second copy of one.

#include <flux/socket/socket.h>
#include <flux/address.h>
#include <flux/peer/peer.h>
#include <flux/peer/peer_handle.h>
#include <flux/transfer/transfer.h>

#include "flux_net.h"
#include "udp_raw.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <thread>
#include <vector>

namespace flux   = bcp::flux;
namespace common = bcp::common;

namespace
{
    using Clock = std::chrono::steady_clock;

    uint64_t NowMicros()
    {
        return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
            Clock::now().time_since_epoch()).count());
    }

    constexpr uint64_t LINK_KBIT    = 50000;
    constexpr uint64_t OWD_MICROS   = 20000;
    constexpr uint64_t QUEUE_BYTES  = 250000;
    constexpr size_t   MAX_DATAGRAM = 2048;

    struct LossModel
    {
        const char* label;
        uint32_t lossPPM;        ///< independent loss, applied when geEnterPPM is zero
        uint32_t geEnterPPM;     ///< chance per packet of entering the bad state
        uint32_t geExitPPM;      ///< chance per packet of leaving it, mean burst is 1e6/exit
        uint32_t geBadLossPct;   ///< share of packets lost while inside
    };

    // Deterministic xorshift, so two runs meet the same loss pattern.
    uint64_t rngState = 0x243F6A8885A308D3ull;
    uint32_t NextRandom()
    {
        rngState ^= rngState >> 12;
        rngState ^= rngState << 25;
        rngState ^= rngState >> 27;
        return static_cast<uint32_t>((rngState * 0x2545F4914F6CDD1Dull) >> 32);
    }

    int RecvFrom(udp_raw::Socket fd, uint8_t* buffer, int max, sockaddr_storage& from,
                 int& fromLen)
    {
#ifdef _WIN32
        int len = sizeof(from);
        const int n = ::recvfrom(fd, reinterpret_cast<char*>(buffer), max, 0,
                                 reinterpret_cast<sockaddr*>(&from), &len);
        fromLen = len;
        return n;
#else
        socklen_t len = sizeof(from);
        const int n = static_cast<int>(::recvfrom(fd, buffer, static_cast<size_t>(max), 0,
                                                  reinterpret_cast<sockaddr*>(&from), &len));
        fromLen = static_cast<int>(len);
        return n;
#endif
    }

    uint16_t PortOf(const sockaddr_storage& addr)
    {
        if (addr.ss_family == AF_INET6)
            return ntohs(reinterpret_cast<const sockaddr_in6&>(addr).sin6_port);
        return ntohs(reinterpret_cast<const sockaddr_in&>(addr).sin_port);
    }

    /** The relay. Listens on one port, forwards to the receiver, and forwards
        replies back to whoever spoke first. Both directions cross the same
        model, each with its own wire and its own queue. */
    void RunShaper(uint16_t listenPort, uint16_t receiverPort, LossModel loss,
                   std::atomic<bool>& stop)
    {
        struct Direction
        {
            uint64_t linkFreeMicros = 0;
            uint64_t queuedBytes    = 0;
            bool     geBad          = false;
        };
        struct Pending
        {
            uint64_t             dueMicros;
            bool                 toReceiver;
            std::vector<uint8_t> bytes;
        };

        udp_raw::Socket fd = udp_raw::MakeBound(listenPort);
        if (udp_raw::Bad(fd)) return;

        const flux::Address receiverAddr = flux_net::Loopback(receiverPort);
        sockaddr_storage senderAddr{};
        int  senderAddrLen = 0;
        bool haveSender    = false;

        // Micros to put one byte on the wire, in fixed point so the product
        // with a packet length never rounds to zero.
        const uint64_t microsPerByteQ16 = (8000ull << 16) / LINK_KBIT;

        Direction toReceiver, toSender;
        std::deque<Pending> line;
        uint8_t buffer[MAX_DATAGRAM];

        while (!stop.load(std::memory_order_relaxed))
        {
            for (;;)
            {
                sockaddr_storage from{};
                int fromLen = 0;
                const int n = RecvFrom(fd, buffer, sizeof(buffer), from, fromLen);
                if (n <= 0) break;

                const bool fromReceiver = PortOf(from) == receiverPort;
                if (!fromReceiver && !haveSender)
                {
                    senderAddr    = from;
                    senderAddrLen = fromLen;
                    haveSender    = true;
                }

                Direction& direction = fromReceiver ? toSender : toReceiver;
                const uint64_t len = static_cast<uint64_t>(n);

                bool lost;
                if (loss.geEnterPPM != 0)
                {
                    // Walk the chain first, so the state this packet meets is
                    // the one its own transition produced. Entering and losing
                    // on the same packet is what makes a burst begin at a
                    // packet rather than between two.
                    if (direction.geBad)
                    {
                        if ((NextRandom() % 1000000u) < loss.geExitPPM)
                            direction.geBad = false;
                    }
                    else if ((NextRandom() % 1000000u) < loss.geEnterPPM)
                        direction.geBad = true;
                    lost = direction.geBad
                        && (NextRandom() % 100u) < loss.geBadLossPct;
                }
                else
                    lost = loss.lossPPM != 0
                        && (NextRandom() % 1000000u) < loss.lossPPM;

                if (lost || direction.queuedBytes + len > QUEUE_BYTES) continue;

                const uint64_t now       = NowMicros();
                const uint64_t serialise = (microsPerByteQ16 * len) >> 16;
                const uint64_t departs   = (now > direction.linkFreeMicros
                                              ? now : direction.linkFreeMicros) + serialise;
                direction.linkFreeMicros = departs;
                direction.queuedBytes   += len;

                Pending pending;
                pending.dueMicros  = departs + OWD_MICROS;
                pending.toReceiver = !fromReceiver;
                pending.bytes.assign(buffer, buffer + n);
                line.push_back(std::move(pending));
            }

            const uint64_t now = NowMicros();
            while (!line.empty() && line.front().dueMicros <= now)
            {
                Pending& pending = line.front();
                Direction& direction = pending.toReceiver ? toReceiver : toSender;
                if (pending.toReceiver)
                    udp_raw::SendTo(fd, pending.bytes.data(),
                                    static_cast<int>(pending.bytes.size()), receiverAddr);
                else if (haveSender)
                    ::sendto(fd, reinterpret_cast<const char*>(pending.bytes.data()),
                             static_cast<int>(pending.bytes.size()), 0,
                             reinterpret_cast<const sockaddr*>(&senderAddr), senderAddrLen);
                const uint64_t len = pending.bytes.size();
                direction.queuedBytes -= len < direction.queuedBytes
                    ? len : direction.queuedBytes;
                line.pop_front();
            }

            // Spin instead of sleeping. The shortest sleep Windows grants is
            // a timer tick, near 16 ms unless the process raises the rate,
            // and a tick of delay on every release is jitter the congestion
            // controller reads as queue growth: measured on one such machine,
            // the clean row fell from 96 percent of the link to 39. One core
            // for the relay is the price of releasing packets when the model
            // says they are due.
            {
                const uint64_t at = NowMicros();
                uint64_t until    = at + 200;
                if (!line.empty() && line.front().dueMicros < until)
                    until = line.front().dueMicros;
                while (NowMicros() < until) { /* the relay owns this core */ }
            }
        }
        udp_raw::Close(fd);
    }

    struct Receiver
    {
        flux::Socket*         socket = nullptr;
        std::vector<uint8_t>  buffer;
        std::atomic<uint64_t> bytes{0};
        std::atomic<bool>     done{false};
    };

    void OnTransferOffered(void* context, const flux::EventInfo& info)
    {
        if (!info.Has(flux::SocketEvent::TRANSFER_INCOMING)) return;
        Receiver& receiver = *static_cast<Receiver*>(context);
        flux::TransferRequest request =
            receiver.socket->PendingTransfer(info.Flow(), info.Peer());
        if (!request.Valid()) return;
        receiver.buffer.resize(static_cast<size_t>(request.Length()));
        if (request.Allow(receiver.buffer.data()) != common::Error::Ok)
            (void)request.Reject();
    }

    flux::Socket::Config EndpointConfig(uint16_t port)
    {
        flux::Socket::Config config{};
        config.type     = flux_net::BACKEND;
        config.port     = port;
        config.maxPeers = 4;
        config.flows.outCount         = 4;
        config.flows.inCount          = 4;
        config.flows.recvGrant        = 0;
        config.flows.transferOutCount = 2;
        config.flows.transferInCount  = 2;
        config.flows.maxTransferBytes = 4ull << 30;
        return config;
    }

    /** One transfer across one configuration of the link. Returns the seconds
        it took, or zero when it missed the deadline. */
    double RunScenario(LossModel loss, uint64_t payloadBytes, uint16_t basePort)
    {
        const uint16_t shaperPort   = basePort;
        const uint16_t senderPort   = static_cast<uint16_t>(basePort + 1);
        const uint16_t receiverPort = static_cast<uint16_t>(basePort + 2);

        std::atomic<bool> stopShaper{false};
        std::thread shaper(RunShaper, shaperPort, receiverPort, loss,
                           std::ref(stopShaper));

        Receiver state;
        flux::Socket receiver;
        flux::Socket::Config receiverConfig = EndpointConfig(receiverPort);
        receiverConfig.events.hook       = OnTransferOffered;
        receiverConfig.events.context    = &state;
        receiverConfig.events.subscribed = flux::ToBits(flux::SocketEvent::TRANSFER_INCOMING);
        state.socket = &receiver;
        if (receiver.Init(receiverConfig) != common::Error::Ok) return 0.0;

        flux::Socket sender;
        if (sender.Init(EndpointConfig(senderPort)) != common::Error::Ok) return 0.0;

        std::atomic<bool> stopReceiver{false};
        std::thread receiverThread([&]
        {
            flux::PacketSlotHandle inbox[64];
            while (!stopReceiver.load(std::memory_order_relaxed))
            {
                receiver.Update();
                { flux::PollCursor cursor = receiver.Poll(inbox, 64); while (cursor.Next()) {} }
                flux::TransferView finished[2];
                const size_t count = receiver.PollTransfers(finished, 2);
                for (size_t i = 0; i < count; ++i)
                {
                    if (!finished[i].Bytes()) continue;
                    state.bytes = finished[i].Length();
                    (void)receiver.CompleteTransfer(finished[i].Flow(), finished[i].Peer());
                    state.done = true;
                }
                receiver.Flush();
            }
            for (auto& handle : inbox) handle = flux::PacketSlotHandle::Invalid();
        });

        const flux::Address via = flux_net::Loopback(shaperPort);
        (void)sender.Connect(via);

        // Establish before the clock, so the handshake sits outside the
        // window on every row and the rows compare transfers alone.
        bool established = false;
        {
            flux::PacketSlotHandle inbox[16];
            const auto until = Clock::now() + std::chrono::seconds(10);
            while (Clock::now() < until)
            {
                sender.Update();
                { flux::PollCursor cursor = sender.Poll(inbox, 16); while (cursor.Next()) {} }
                sender.Flush();
                if (flux_net::Established(sender, via)) { established = true; break; }
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
            for (auto& handle : inbox) handle = flux::PacketSlotHandle::Invalid();
        }

        double seconds = 0.0;
        if (established)
        {
            std::vector<uint8_t> payload(static_cast<size_t>(payloadBytes), 0x5A);
            const double floorSeconds =
                static_cast<double>(payloadBytes) * 8.0 / (LINK_KBIT * 1000.0);
            const auto start    = Clock::now();
            const auto deadline = start + std::chrono::seconds(
                static_cast<int64_t>(floorSeconds * 5.0) + 10);

            if (sender.SendTransfer(1, via, payload.data(), payloadBytes)
                    == common::Error::Ok)
            {
                flux::PacketSlotHandle inbox[64];
                while (!state.done.load(std::memory_order_relaxed)
                       && Clock::now() < deadline)
                {
                    sender.Update();
                    { flux::PollCursor cursor = sender.Poll(inbox, 64); while (cursor.Next()) {} }
                    flux::TransferView finished[2];
                    (void)sender.PollTransfers(finished, 2);
                    sender.Flush();
                }
                for (auto& handle : inbox) handle = flux::PacketSlotHandle::Invalid();
            }
            if (state.done.load(std::memory_order_relaxed)
                && state.bytes.load(std::memory_order_relaxed) == payloadBytes)
                seconds = std::chrono::duration<double>(Clock::now() - start).count();
        }

        stopReceiver = true;
        receiverThread.join();
        stopShaper = true;
        shaper.join();
        sender.Shutdown();
        receiver.Shutdown();
        return seconds;
    }
}
