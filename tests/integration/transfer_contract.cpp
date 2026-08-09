// What the transfer entry points promise when they refuse.
//
// Every case here is a documented guarantee from socket.h or transfer.h rather
// than an observation of what the code does today. The guards are the contract:
// a caller that gets Ok from SendTransfer has been told the run is under way
// and that its buffer is now being read, so each way that can fail has to fail
// with the code the header names and not merely fail somehow.
//
// The refusal path matters more here than in most places, because a transfer
// hands the library a pointer into application memory and keeps it. A guard
// that misreports leaves an application either freeing a buffer the library is
// still reading, or holding one it could have released.
#include "flux_net.h"

#include <flux/socket/socket.h>
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
    constexpr uint16_t TRANSFER_ID = 3;
    constexpr uint64_t CEILING     = 64 * 1024;

    flux::Socket::Config Config(uint16_t port, uint32_t outCount, uint32_t inCount)
    {
        flux::Socket::Config config{};
        config.type     = flux_net::BACKEND;
        config.port     = port;
        config.maxPeers = 4;
        config.flows.outCount         = 4;
        config.flows.inCount          = 4;
        config.flows.transferOutCount = outCount;
        config.flows.transferInCount  = inCount;
        config.flows.maxTransferBytes = CEILING;
        return config;
    }

    /** Drives both sockets for a while. Transfers move on the tick, so a test
        that only sends never sees anything happen. */
    void Pump(flux::Socket& a, flux::Socket& b, int rounds)
    {
        flux::PacketSlotHandle inbox[16];
        for (int i = 0; i < rounds; ++i)
        {
            a.Update();
            b.Update();
            { flux::PollCursor cursor = a.Poll(inbox, 16); while (cursor.Next()) {} }
            { flux::PollCursor cursor = b.Poll(inbox, 16); while (cursor.Next()) {} }
            a.Flush();
            b.Flush();
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        for (auto& handle : inbox) handle = flux::PacketSlotHandle::Invalid();
    }

    // A socket given no transfer pool refuses transfers outright, which is what
    // lets a socket that never moves buffers pay nothing for the feature.
    void no_pool_refuses()
    {
        flux::Socket sender, receiver;
        CHECK(sender.Init(Config(9810, 0, 0)) == common::Error::Ok);
        CHECK(receiver.Init(Config(9811, 2, 2)) == common::Error::Ok);

        const flux::Address to = Loopback(9811);
        CHECK(sender.Connect(to) == common::Error::Ok);
        CHECK(flux_net::PumpUntilEstablished(sender, Loopback(9810), receiver, to));

        std::vector<uint8_t> payload(1024, 0x5A);
        CHECK(sender.SendTransfer(TRANSFER_ID, to, payload.data(), payload.size())
              == common::Error::InvalidState);

        sender.Shutdown();
        receiver.Shutdown();
    }

    // The four argument guards, and the ceiling. Zero length is refused so that
    // a pending length of zero can only ever mean nothing pending, which is
    // what PendingTransfer relies on to report an invalid request.
    void arguments_and_ceiling()
    {
        flux::Socket sender, receiver;
        CHECK(sender.Init(Config(9812, 2, 2)) == common::Error::Ok);
        CHECK(receiver.Init(Config(9813, 2, 2)) == common::Error::Ok);

        const flux::Address to = Loopback(9813);
        CHECK(sender.Connect(to) == common::Error::Ok);
        CHECK(flux_net::PumpUntilEstablished(sender, Loopback(9812), receiver, to));

        std::vector<uint8_t> payload(1024, 0x5A);

        CHECK(sender.SendTransfer(TRANSFER_ID, to, nullptr, payload.size())
              == common::Error::InvalidParam);
        CHECK(sender.SendTransfer(TRANSFER_ID, to, payload.data(), 0)
              == common::Error::InvalidParam);
        CHECK(sender.SendTransfer(TRANSFER_ID, to, payload.data(), CEILING + 1)
              == common::Error::TooLarge);

        // A peer this socket has never spoken to is not a transfer target. The
        // handshake need not have finished, but the peer has to exist.
        CHECK(sender.SendTransfer(TRANSFER_ID, Loopback(9899), payload.data(),
                                  payload.size()) == common::Error::NotFound);

        sender.Shutdown();
        receiver.Shutdown();
    }

    // One transfer at a time per id per peer, since the pair is what names it.
    void second_on_the_same_id_is_refused()
    {
        flux::Socket sender, receiver;
        CHECK(sender.Init(Config(9814, 2, 2)) == common::Error::Ok);
        CHECK(receiver.Init(Config(9815, 2, 2)) == common::Error::Ok);

        const flux::Address to = Loopback(9815);
        CHECK(sender.Connect(to) == common::Error::Ok);
        CHECK(flux_net::PumpUntilEstablished(sender, Loopback(9814), receiver, to));

        std::vector<uint8_t> first(4096, 0x11), second(4096, 0x22);
        CHECK(sender.SendTransfer(TRANSFER_ID, to, first.data(), first.size())
              == common::Error::Ok);
        CHECK(sender.SendTransfer(TRANSFER_ID, to, second.data(), second.size())
              == common::Error::AlreadyPending);

        // A different id to the same peer is a different transfer and is fine.
        CHECK(sender.SendTransfer(TRANSFER_ID + 1, to, second.data(), second.size())
              == common::Error::Ok);

        sender.Shutdown();
        receiver.Shutdown();
    }

    // Queries answer for something that is not there without reaching into a
    // slot that may since have been reused.
    void queries_on_nothing()
    {
        flux::Socket socket;
        CHECK(socket.Init(Config(9816, 2, 2)) == common::Error::Ok);

        const flux::Address stranger = Loopback(9898);

        CHECK(socket.TransferProgress(TRANSFER_ID, stranger) == 0);
        CHECK(!socket.PendingTransfer(TRANSFER_ID, stranger).Valid());
        CHECK(socket.CompleteTransfer(TRANSFER_ID, stranger) == common::Error::NotFound);

        flux::TransferView finished[2];
        CHECK(socket.PollTransfers(finished, 2) == 0);

        socket.Shutdown();
    }

    // A request that names nothing answers InvalidState rather than reaching
    // for a socket it does not have. This is the default-constructed case an
    // application meets when it asks after the announcement was withdrawn.
    void invalid_request_answers_refuse()
    {
        flux::TransferRequest request;
        CHECK(!request.Valid());
        CHECK(request.Length() == 0);

        uint8_t buffer[16] = {};
        CHECK(request.Allow(buffer) == common::Error::InvalidState);
        CHECK(request.Reject() == common::Error::InvalidState);
    }

    // Allow refuses a null destination. The library writes packets straight to
    // their offsets in this buffer, so accepting null would be accepting a
    // transfer with nowhere to put it.
    void allow_refuses_a_null_buffer()
    {
        flux::Socket sender, receiver;
        CHECK(sender.Init(Config(9817, 2, 2)) == common::Error::Ok);
        CHECK(receiver.Init(Config(9818, 2, 2)) == common::Error::Ok);

        const flux::Address to   = Loopback(9818);
        const flux::Address from = Loopback(9817);
        CHECK(sender.Connect(to) == common::Error::Ok);
        CHECK(flux_net::PumpUntilEstablished(sender, from, receiver, to));

        std::vector<uint8_t> payload(4096, 0x33);
        CHECK(sender.SendTransfer(TRANSFER_ID, to, payload.data(), payload.size())
              == common::Error::Ok);

        // Pump until the announcement has landed and the receiver can see it.
        bool sawRequest = false;
        for (int i = 0; i < 200 && !sawRequest; ++i)
        {
            Pump(sender, receiver, 1);
            flux::TransferRequest request = receiver.PendingTransfer(TRANSFER_ID, from);
            if (!request.Valid()) continue;
            sawRequest = true;
            CHECK(request.Length() == payload.size());
            CHECK(request.Allow(nullptr) == common::Error::InvalidParam);
        }
        CHECK(sawRequest);

        sender.Shutdown();
        receiver.Shutdown();
    }
}

int main()
{
    no_pool_refuses();
    arguments_and_ceiling();
    second_on_the_same_id_is_refused();
    queries_on_nothing();
    invalid_request_answers_refuse();
    allow_refuses_a_null_buffer();
    return test::report();
}
