// A transfer end to end, and what each side is promised along the way.
//
// The payload is positional rather than constant: byte i is derived from i, so
// a packet written at the wrong offset, a duplicate placed twice or a hole left
// unfilled all change the bytes rather than merely the count. A length check
// alone would pass through every one of those.
//
// Four promises get their own case. The bytes arrive whole. The two directions
// report differently from PollTransfers, the receiver handing over the buffer
// and the sender handing back its source. An id is reusable once the receiver
// says it is done, which is the backpressure the design puts in the
// application's hands. And a refused transfer completes as Refused rather than
// stalling, which is the path a receiver takes when it will not find room.
#include "flux_net.h"

#include <flux/socket/socket.h>
#include <flux/socket/socket_events.h>
#include <flux/transfer/transfer.h>

#include "harness.h"

#include <chrono>
#include <cstdint>
#include <thread>
#include <vector>

namespace flux   = bcp::flux;
namespace common = bcp::common;

using flux_net::Loopback;

namespace
{
    constexpr uint16_t TRANSFER_ID = 7;
    constexpr size_t   PAYLOAD     = 300 * 1024;

    /** Byte i as a function of i, so a misplaced packet is a wrong byte rather
        than a right one in the wrong order. */
    uint8_t ByteAt(size_t i)
    {
        return static_cast<uint8_t>((i * 131u) ^ (i >> 7) ^ (i >> 15));
    }

    std::vector<uint8_t> MakePayload(size_t size)
    {
        std::vector<uint8_t> out(size);
        for (size_t i = 0; i < size; ++i) out[i] = ByteAt(i);
        return out;
    }

    /** What the receiving side does with an announcement, and what it recorded
        while doing it. */
    struct Receiver
    {
        flux::Socket*        socket  = nullptr;
        bool                 reject  = false;
        std::vector<uint8_t> buffer;
        uint64_t             announcedLength = 0;
        int                  announcements   = 0;
        bool                 handlerSawValid = false;
    };

    /** PendingTransfer and its answer are documented as legal from inside the
        event handler, so that is where this test answers from. */
    void OnEvent(void* context, const flux::EventInfo& info)
    {
        if (!info.Has(flux::SocketEvent::TRANSFER_INCOMING)) return;
        Receiver& state = *static_cast<Receiver*>(context);
        ++state.announcements;

        flux::TransferRequest request =
            state.socket->PendingTransfer(info.Flow(), info.Peer());
        if (!request.Valid()) return;
        state.handlerSawValid   = true;
        state.announcedLength   = request.Length();

        if (state.reject) { (void)request.Reject(); return; }

        state.buffer.assign(static_cast<size_t>(request.Length()), 0);
        if (request.Allow(state.buffer.data()) != common::Error::Ok)
            (void)request.Reject();
    }

    flux::Socket::Config Config(uint16_t port)
    {
        flux::Socket::Config config{};
        config.type     = flux_net::BACKEND;
        config.port     = port;
        config.maxPeers = 4;
        config.flows.outCount         = 4;
        config.flows.inCount          = 4;
        config.flows.transferOutCount = 2;
        config.flows.transferInCount  = 2;
        config.flows.maxTransferBytes = 4ull << 20;
        return config;
    }

    /** One tick of both sides, draining finished transfers into the caller's
        record of what each end was told. */
    struct Finished
    {
        bool          sender   = false;
        bool          receiver = false;
        const void*   senderBytes   = nullptr;
        const void*   receiverBytes = nullptr;
        uint64_t      receiverLength = 0;
        common::Error senderOutcome  = common::Error::Ok;
    };

    void PumpOnce(flux::Socket& sender, flux::Socket& receiver, Finished& seen)
    {
        flux::PacketSlotHandle inbox[32];
        sender.Update();
        receiver.Update();
        { flux::PollCursor cursor = sender.Poll(inbox, 32);   while (cursor.Next()) {} }
        { flux::PollCursor cursor = receiver.Poll(inbox, 32); while (cursor.Next()) {} }

        flux::TransferView done[2];
        for (size_t i = 0, n = sender.PollTransfers(done, 2); i < n; ++i)
        {
            seen.sender        = true;
            seen.senderBytes   = done[i].Bytes();
            seen.senderOutcome = done[i].Outcome();
        }
        for (size_t i = 0, n = receiver.PollTransfers(done, 2); i < n; ++i)
        {
            seen.receiver       = true;
            seen.receiverBytes  = done[i].Bytes();
            seen.receiverLength = done[i].Length();
        }

        sender.Flush();
        receiver.Flush();
        for (auto& handle : inbox) handle = flux::PacketSlotHandle::Invalid();
    }

    bool PumpUntilBothFinished(flux::Socket& sender, flux::Socket& receiver,
                               Finished& seen, int maxRounds)
    {
        for (int i = 0; i < maxRounds; ++i)
        {
            PumpOnce(sender, receiver, seen);
            if (seen.sender && seen.receiver) return true;
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        return false;
    }

    // The whole run: bytes intact, both views as documented, progress moving,
    // and the id reusable once the receiver releases it.
    void a_transfer_arrives_whole()
    {
        Receiver state;
        flux::Socket sender, receiver;

        flux::Socket::Config receiverConfig = Config(9821);
        receiverConfig.events.hook       = OnEvent;
        receiverConfig.events.context    = &state;
        receiverConfig.events.subscribed = flux::ToBits(flux::SocketEvent::TRANSFER_INCOMING);
        state.socket = &receiver;

        CHECK(receiver.Init(receiverConfig) == common::Error::Ok);
        CHECK(sender.Init(Config(9820)) == common::Error::Ok);

        const flux::Address to   = Loopback(9821);
        const flux::Address from = Loopback(9820);
        CHECK(sender.Connect(to) == common::Error::Ok);
        CHECK(flux_net::PumpUntilEstablished(sender, from, receiver, to));

        const std::vector<uint8_t> payload = MakePayload(PAYLOAD);
        CHECK(sender.SendTransfer(TRANSFER_ID, to, payload.data(), payload.size())
              == common::Error::Ok);

        Finished seen;
        CHECK(PumpUntilBothFinished(sender, receiver, seen, 20000));

        // The announcement reached the handler, carrying the length the sender
        // named, and the handler could answer from inside itself.
        CHECK(state.announcements >= 1);
        CHECK(state.handlerSawValid);
        CHECK(state.announcedLength == payload.size());

        // The sender is told its source is free and that the peer took it.
        CHECK(seen.sender);
        CHECK(seen.senderBytes == nullptr);
        CHECK(seen.senderOutcome == common::Error::Ok);

        // The receiver is handed the buffer it supplied, whole.
        CHECK(seen.receiver);
        CHECK(seen.receiverBytes == state.buffer.data());
        CHECK(seen.receiverLength == payload.size());
        CHECK(state.buffer.size() == payload.size());
        CHECK(state.buffer == payload);

        // Progress reached the whole length on the receiving side.
        CHECK(receiver.TransferProgress(TRANSFER_ID, from) == payload.size());

        // Held until released, then the id is free for the next one.
        CHECK(receiver.CompleteTransfer(TRANSFER_ID, from) == common::Error::Ok);
        CHECK(receiver.CompleteTransfer(TRANSFER_ID, from) == common::Error::NotFound);

        const std::vector<uint8_t> again = MakePayload(64 * 1024);
        CHECK(sender.SendTransfer(TRANSFER_ID, to, again.data(), again.size())
              == common::Error::Ok);

        Finished second;
        CHECK(PumpUntilBothFinished(sender, receiver, second, 20000));
        CHECK(second.senderOutcome == common::Error::Ok);
        CHECK(state.buffer == again);

        sender.Shutdown();
        receiver.Shutdown();
    }

    // A refusal is an answer. The sender's transfer completes as Refused so it
    // learns its buffer is free, rather than waiting out a stall timeout.
    void a_refused_transfer_completes_as_refused()
    {
        Receiver state;
        state.reject = true;

        flux::Socket sender, receiver;
        flux::Socket::Config receiverConfig = Config(9823);
        receiverConfig.events.hook       = OnEvent;
        receiverConfig.events.context    = &state;
        receiverConfig.events.subscribed = flux::ToBits(flux::SocketEvent::TRANSFER_INCOMING);
        state.socket = &receiver;

        CHECK(receiver.Init(receiverConfig) == common::Error::Ok);
        CHECK(sender.Init(Config(9822)) == common::Error::Ok);

        const flux::Address to   = Loopback(9823);
        const flux::Address from = Loopback(9822);
        CHECK(sender.Connect(to) == common::Error::Ok);
        CHECK(flux_net::PumpUntilEstablished(sender, from, receiver, to));

        const std::vector<uint8_t> payload = MakePayload(128 * 1024);
        CHECK(sender.SendTransfer(TRANSFER_ID, to, payload.data(), payload.size())
              == common::Error::Ok);

        Finished seen;
        bool senderFinished = false;
        for (int i = 0; i < 20000 && !senderFinished; ++i)
        {
            PumpOnce(sender, receiver, seen);
            senderFinished = seen.sender;
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }

        CHECK(state.handlerSawValid);
        CHECK(senderFinished);
        CHECK(seen.senderOutcome == common::Error::Refused);
        CHECK(seen.senderBytes == nullptr);

        // Nothing was placed, so the receiver has no finished transfer to
        // release and no bytes to hand over.
        CHECK(!seen.receiver);
        CHECK(receiver.CompleteTransfer(TRANSFER_ID, from) == common::Error::NotFound);

        // The refusal freed the id, so the sender may try again.
        CHECK(sender.SendTransfer(TRANSFER_ID, to, payload.data(), payload.size())
              == common::Error::Ok);

        sender.Shutdown();
        receiver.Shutdown();
    }
}

int main()
{
    a_transfer_arrives_whole();
    a_refused_transfer_completes_as_refused();
    return test::report();
}
