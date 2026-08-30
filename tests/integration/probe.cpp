// The probe: measuring a path without opening a session.
//
// What is being checked is mostly what does NOT happen. A probe has to come
// back with a figure, but it also has to leave both sockets exactly as it found
// them - no peer registered on either side, no liveness disturbed, nothing that
// has to be aged out afterwards - because that is the whole reason it exists.
// A caller weighing several strangers should be able to ask all of them and
// open a session with one.
//
// The seeding case is the one exception, and it is deliberately narrow: a probe
// may fill in the smoothed round trip of a peer that already exists and has
// never been measured, where the alternative is the configured guess, and may
// not touch the remembered minimum even then.
#include <flux/socket/socket.h>

#include "flux_net.h"
#include "harness.h"

#include <chrono>
#include <cstdint>
#include <thread>

using bcp::flux::Address;
using bcp::flux::Socket;
using flux_net::BACKEND;
using flux_net::Loopback;
using flux_net::PumpUntilEstablished;
namespace common = bcp::common;

namespace
{
    constexpr uint16_t PROBER  = 47401;
    constexpr uint16_t ANSWER  = 47402;

    bool Boot(Socket& socket, uint16_t port)
    {
        Socket::Config config{ .type = BACKEND, .port = port,
                               .maxPeers = 8, .pendingPacketCount = 8 };
        return socket.Init(config) == common::Error::Ok;
    }

    // Drives both sockets until the prober has collected a result, or the
    // budget runs out. Returns how many results came back.
    uint32_t PumpForProbe(Socket& prober, Socket& answerer,
                          Socket::ProbeResult* out, uint32_t max,
                          int maxIterations = 200)
    {
        bcp::flux::PacketSlotHandle sink[16];
        for (int i = 0; i < maxIterations; ++i)
        {
            prober.Update();
            answerer.Update();
            prober.Poll(sink, 16);
            answerer.Poll(sink, 16);

            const uint32_t got = prober.PollProbes(out, max);
            if (got != 0) return got;

            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        return 0;
    }
}

// The measurement arrives, and it is a measurement: a loopback round trip is
// small but never zero, and zero is reserved for the timeout.
static void a_probe_measures_the_path()
{
    Socket prober, answerer;
    CHECK(Boot(prober, PROBER));
    CHECK(Boot(answerer, ANSWER));

    CHECK(prober.ProbeAddress(Loopback(ANSWER)) == common::Error::Ok);

    Socket::ProbeResult results[4];
    const uint32_t got = PumpForProbe(prober, answerer, results, 4);
    CHECK(got == 1);
    if (got == 1)
    {
        CHECK(results[0].address == Loopback(ANSWER));
        CHECK(results[0].rttMicros != 0);
    }

    prober.Shutdown();
    answerer.Shutdown();
}

// The guarantee the whole design rests on. Neither side may end up with a peer
// for the other, because a probe is a question and not an introduction.
static void a_probe_registers_nothing_on_either_side()
{
    Socket prober, answerer;
    CHECK(Boot(prober, PROBER + 2));
    CHECK(Boot(answerer, ANSWER + 2));

    const Address answerAddr = Loopback(ANSWER + 2);
    const Address proberAddr = Loopback(PROBER + 2);

    CHECK(prober.ProbeAddress(answerAddr) == common::Error::Ok);

    Socket::ProbeResult results[4];
    CHECK(PumpForProbe(prober, answerer, results, 4) == 1);

    // The asking side never registered the address it asked about.
    CHECK(prober.GetPeer(answerAddr).Failed());

    // And the answering side never registered whoever asked, which is what
    // keeps a flood of probes from filling its peer table.
    CHECK(answerer.GetPeer(proberAddr).Failed());

    prober.Shutdown();
    answerer.Shutdown();
}

// A probe to nowhere costs one slot for one timeout and then reports itself as
// a timeout, which is the only failure a probe has. Zero is the figure that
// carries, which is why a real measurement is never allowed to be zero.
static void an_unanswered_probe_expires_and_frees_its_slot()
{
    Socket prober;
    CHECK(Boot(prober, PROBER + 4));

    // Nothing is bound here, so nothing will ever answer.
    const Address nowhere = Loopback(ANSWER + 40);
    CHECK(prober.ProbeAddress(nowhere) == common::Error::Ok);

    // Before the deadline there is nothing to collect: the probe is still a
    // question, not yet a failed one.
    Socket::ProbeResult results[4];
    prober.Update();
    CHECK(prober.PollProbes(results, 4) == 0);

    // Past it, the slot reports itself rather than being held forever. Waiting
    // out a real deadline is the only way to see this: the timeout is what
    // hands the slot back, so a probe into silence would otherwise cost one
    // slot for the life of the socket.
    const auto deadline = std::chrono::steady_clock::now()
                        + std::chrono::microseconds(
                              bcp::flux::internal::PROBE_TIMEOUT_MICROS_DEFAULT)
                        + std::chrono::milliseconds(250);

    uint32_t got = 0;
    while (std::chrono::steady_clock::now() < deadline)
    {
        prober.Update();
        got = prober.PollProbes(results, 4);
        if (got != 0) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    CHECK(got == 1);
    if (got == 1)
    {
        CHECK(results[0].address == nowhere);
        CHECK(results[0].rttMicros == 0);   // the figure a timeout carries
    }

    // And the slot came back, so the socket can ask again.
    CHECK(prober.ProbeAddress(nowhere) == common::Error::Ok);

    prober.Shutdown();
}

// The outstanding set is bounded, and running out is answered honestly rather
// than by evicting somebody else's question.
static void the_outstanding_set_is_bounded()
{
    Socket prober;
    CHECK(Boot(prober, PROBER + 6));

    // Every slot filled with a probe nobody will answer.
    common::Error last = common::Error::Ok;
    for (uint32_t i = 0; i < bcp::flux::internal::PROBE_OUTSTANDING_DEFAULT + 1; ++i)
    {
        last = prober.ProbeAddress(Loopback(static_cast<uint16_t>(40000 + i)));
        if (last != common::Error::Ok) break;
    }
    CHECK(last == common::Error::LimitReached);

    prober.Shutdown();
}

// The narrow seeding case: a peer that exists but has never been measured picks
// up the probe's figure, and the remembered minimum stays empty because no
// acknowledged packet has been timed yet.
static void a_probe_seeds_an_existing_peer_but_not_its_minimum()
{
    Socket a, b;
    CHECK(Boot(a, PROBER + 8));
    CHECK(Boot(b, ANSWER + 8));

    const Address addrA = Loopback(PROBER + 8);
    const Address addrB = Loopback(ANSWER + 8);

    CHECK(a.Connect(addrB) == common::Error::Ok);
    CHECK(PumpUntilEstablished(a, addrA, b, addrB));

    // A fresh session that has sent no flow traffic has nothing measured: the
    // handshake is not a round trip sample.
    {
        bcp::flux::PeerHandle handle = a.GetPeer(addrB);
        CHECK(!handle.Failed());
        const bcp::flux::Peer* peer = handle.Read();
        CHECK(peer != nullptr);
        if (peer != nullptr) CHECK(peer->rtt.srttMicros == 0);
    }

    CHECK(a.ProbeAddress(addrB) == common::Error::Ok);
    Socket::ProbeResult results[4];
    CHECK(PumpForProbe(a, b, results, 4) == 1);

    {
        bcp::flux::PeerHandle handle = a.GetPeer(addrB);
        CHECK(!handle.Failed());
        const bcp::flux::Peer* peer = handle.Read();
        CHECK(peer != nullptr);
        if (peer != nullptr)
        {
            // Seeded, so a deadline built now is measured rather than guessed.
            CHECK(peer->rtt.srttMicros != 0);

            // But the minimum is still empty, so QueueMicros reports no queue
            // rather than the difference against a floor a probe invented.
            CHECK(peer->rtt.MinRttMicros() == 0);
            CHECK(peer->rtt.QueueMicros()  == 0);
        }
    }

    a.Shutdown();
    b.Shutdown();
}

int main()
{
    a_probe_measures_the_path();
    a_probe_registers_nothing_on_either_side();
    an_unanswered_probe_expires_and_frees_its_slot();
    the_outstanding_set_is_bounded();
    a_probe_seeds_an_existing_peer_but_not_its_minimum();
    return test::report();
}
