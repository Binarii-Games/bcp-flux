// Moving something large without chunking it.
//
// bulk_transfer.cpp shows the other way: the application cuts a payload into
// packet-sized pieces, offers each one, and backs off when the window is full.
// That loop is the whole trick there, and the reason it exists is that every
// unacknowledged packet holds a copy of its bytes, so the window has to be
// small enough to afford them.
//
// A transfer flow removes both. The sender hands over one buffer and a length
// and never touches the wire again. Retransmits are re-read out of that same
// buffer, so nothing is staged per packet, so the window can be deep enough
// that the path rather than the memory is what bounds it. The receiver is
// asked for a buffer once, up front, and each packet is written straight to
// its own offset in it.
//
// What the receiver has to do is answer. A transfer announces its size before
// it sends anything, the application is told, and it either allows the
// transfer into a buffer it supplies or rejects it. Neither answer is
// optional: a peer that is never answered waits.
//
// Both sides run in one process here, so the numbers say nothing about a
// network.
//
//     ./transfer_flow

#include <common/log.h>

#include <flux/address.h>
#include <flux/transfer/transfer.h>
#include <flux/socket/packet_slot.h>
#include <flux/socket/socket.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <thread>
#include <vector>

#include "setup.h"

namespace common = bcp::common;
namespace flux   = bcp::flux;

constexpr uint16_t PORT_A  = 9570;
constexpr uint16_t PORT_B  = 9571;
constexpr uint16_t FLOW_ID = 12;

constexpr uint64_t PAYLOAD_BYTES = 4ull * 1024ull * 1024ull;

// The most one transfer may ask this receiver to find room for. An
// announcement past it is refused before any buffer is looked for.
constexpr uint64_t ACCEPT_LIMIT = 16ull * 1024ull * 1024ull;

// A counting pattern rather than random bytes, so a gap or a misplaced packet
// shows up as a wrong value at a known offset.
static uint8_t ByteAt(uint64_t offset)
{
    return static_cast<uint8_t>((offset * 31u + (offset >> 8)) & 0xFF);
}

namespace
{
    struct Receiver
    {
        flux::Socket*        socket = nullptr;
        std::vector<uint8_t> buffer;          ///< where an allowed transfer lands
        std::atomic<bool>    complete{false};
    };

    Receiver g_receiver;
}

// A peer announced a transfer. The event says which flow and which peer, and
// the length is held on the association, so ask for it and answer.
//
// Calling back into the socket from here is allowed: events dispatch with no
// peer or association lock held, and the association stays alive across the
// handler for exactly this. The one thing a handler must not do is call Poll.
static void OnSocketEvent(void* context, const flux::EventInfo& info)
{
    if (!info.Has(flux::SocketEvent::TRANSFER_INCOMING)) return;

    Receiver& receiver = *static_cast<Receiver*>(context);

    flux::TransferRequest request =
        receiver.socket->PendingTransfer(info.Flow(), info.Peer());
    if (!request.Valid()) return;

    if (request.Length() > ACCEPT_LIMIT)
    {
        common::LogF(common::LogLevel::Info,
                     "B refusing %llu bytes, over the limit",
                     static_cast<unsigned long long>(request.Length()));
        (void)request.Reject();
        return;
    }

    // Allow accepts Length() by being called, so the buffer has to hold it.
    receiver.buffer.resize(static_cast<size_t>(request.Length()));
    if (request.Allow(receiver.buffer.data()) != common::Error::Ok)
        (void)request.Reject();
}

// B pumps until the transfer completes. Nothing here reassembles anything: the
// bytes were written into the buffer as they arrived, so completion is the
// first moment the whole run is readable and also the last thing to wait for.
static void Receive(flux::Socket& socket)
{
    flux::PacketSlotHandle inbox[64];

    while (!g_receiver.complete.load(std::memory_order_relaxed))
    {
        socket.Flush();
        socket.Update();

        // Poll still has to run: it is what dispatches the announcement event
        // that asks this side for a buffer. It reports no transfers itself.
        { flux::PollCursor cursor = socket.Poll(inbox, 64); while (cursor.Next()) {} }

        flux::TransferView finished[4];
        const size_t count = socket.PollTransfers(finished, 4);
        for (size_t i = 0; i < count; ++i)
        {
            const flux::TransferView& incoming = finished[i];
            if (!incoming.Bytes()) continue;          // an outgoing one, not ours
            const uint8_t* bytes = static_cast<const uint8_t*>(incoming.Bytes());

            bool intact = true;
            for (uint64_t offset = 0; offset < incoming.Length(); ++offset)
            {
                if (bytes[offset] != ByteAt(offset)) { intact = false; break; }
            }

            common::LogF(common::LogLevel::Info, "B received %llu bytes, contents %s",
                         static_cast<unsigned long long>(incoming.Length()),
                         intact ? "intact" : "CORRUPT");

            // Frees the association for this peer's next transfer. Until this
            // call the peer cannot start another one, which is how a receiver
            // that hands each buffer to a worker thread throttles the sender.
            (void)socket.CompleteTransfer(incoming.Flow(), incoming.Peer());
            g_receiver.complete = true;
        }

        std::this_thread::sleep_for(std::chrono::microseconds(200));
    }
}

int main()
{
    flux::Socket a, b;

    flux::Socket::Config config{};
    config.type                       = examples::BACKEND;
    config.maxPeers                   = 8;
    config.pendingPacketCount         = 64;
    config.flows.outCount             = 8;
    config.flows.inCount              = 8;
    config.flows.transferOutCount     = 2;   // the pools must be asked for
    config.flows.transferInCount      = 2;
    config.flows.maxTransferBytes     = ACCEPT_LIMIT;

    config.port = PORT_A;
    if (common::Error e = a.Init(config); e != common::Error::Ok)
    { common::LogF(common::LogLevel::Info, "A init failed: %s", common::ErrorToString(e)); return 1; }

    g_receiver.socket        = &b;
    config.port              = PORT_B;
    config.events.hook       = OnSocketEvent;
    config.events.context    = &g_receiver;
    config.events.subscribed =
        static_cast<uint32_t>(flux::SocketEvent::TRANSFER_INCOMING);
    if (common::Error e = b.Init(config); e != common::Error::Ok)
    { common::LogF(common::LogLevel::Info, "B init failed: %s", common::ErrorToString(e)); return 1; }

    const flux::Address addrB = flux::Address::From("::1", PORT_B).Take();
    (void)a.Connect(addrB);

    std::thread receiver([&] { Receive(b); });

    // The retransmit source. It has to stay alive and unmodified until Poll
    // reports the transfer sent, because that is where resends are read from.
    std::vector<uint8_t> payload(static_cast<size_t>(PAYLOAD_BYTES));
    for (uint64_t offset = 0; offset < PAYLOAD_BYTES; ++offset)
        payload[static_cast<size_t>(offset)] = ByteAt(offset);

    // One call. No chunking, no window to back off against.
    if (common::Error e = a.SendTransfer(FLOW_ID, addrB, payload.data(), PAYLOAD_BYTES);
        e != common::Error::Ok)
    {
        common::LogF(common::LogLevel::Info, "SendTransfer failed: %s",
                     common::ErrorToString(e));
        g_receiver.complete = true;
        receiver.join();
        return 1;
    }

    bool inFlight = true;
    flux::PacketSlotHandle inbox[64];
    while (inFlight)
    {
        a.Flush();
        a.Update();

        { flux::PollCursor cursor = a.Poll(inbox, 64); while (cursor.Next()) {} }

        flux::TransferView finished[4];
        const size_t count = a.PollTransfers(finished, 4);
        for (size_t i = 0; i < count; ++i)
        {
            const flux::TransferView& outgoing = finished[i];
            if (outgoing.Outcome() == common::Error::Ok)
                common::Log(common::LogLevel::Info, "A transfer delivered");
            else
                common::LogF(common::LogLevel::Info, "A transfer failed: %s",
                             common::ErrorToString(outgoing.Outcome()));

            inFlight = false;   // payload may be freed or reused now
        }

        // What is contiguous from the start, so a progress report never
        // counts bytes sitting past a hole.
        static uint64_t lastReported = 0;
        const uint64_t done = a.TransferProgress(FLOW_ID, addrB);
        if (done >= lastReported + (PAYLOAD_BYTES / 4) && inFlight)
        {
            lastReported = done;
            common::LogF(common::LogLevel::Info, "A sent %llu of %llu",
                         (unsigned long long)done,
                         (unsigned long long)PAYLOAD_BYTES);
        }

        std::this_thread::sleep_for(std::chrono::microseconds(200));
    }

    receiver.join();
    a.Shutdown();
    b.Shutdown();
    return 0;
}
