#include <flux/socket/socket.h>

#include <cassert>

#include <common/math.h>
#include <flux/internal/constants.h>

/** Congestion control: how much a peer may keep on the path, and how that
    ceiling moves.

    Two signals, and they answer different questions. Loss says the path could
    not carry what was sent. Delay says a queue is forming, which is the same
    news arriving earlier, before anything has had to be thrown away.

    A controller with only the first has one resting place, and it is a full
    buffer, because a full buffer is the only thing that produces a loss. That
    is where a standing queue comes from, and it is a property of the signal
    rather than of the curve. So the curve decides how fast to climb, the queue
    decides whether to climb at all, and the more cautious of the two wins.

    Nothing here reacts to a deadline. A deadline is a guess about a path nobody
    can see, and it is wrong most often exactly when the path is worst. The
    retransmit timer sends a probe and says so, and the acknowledgement that
    comes back is what says which packets are actually missing.

    It lives beside the socket rather than in the flow table because the budget
    is the peer's and not any one flow's. The gate that spends it is CanSend, in
    the flow table, which is where the packet being admitted is. */

namespace bcp::flux
{
    namespace
    {
        /** CUBIC's window at `elapsedMicros` past the last reduction.

            W(t) = C(t - K)^3 + wMax, where K is how long the curve takes to
            climb back to wMax. Steep while far below the last known good
            window, flat as it arrives there, steep again past it. The shape is
            the point: the previous window is the best guess at what the path
            holds, so most of the time is spent testing that guess rather than
            travelling towards it or running away from it.

            Growth follows time rather than acknowledgements, which is what lets
            a long path recover as fast as a short one. Reno's one packet per
            round trip punishes exactly the paths that can least afford it. */
        uint64_t CubicWindow(uint32_t wMaxBytes, uint64_t elapsedMicros) noexcept
        {
            // C in bytes per second cubed, from the standard 0.4 in packets.
            const uint64_t cBytes = static_cast<uint64_t>(internal::CC_CUBIC_C_SCALED)
                                  * internal::MAX_WIRE_PACKET_SIZE
                                  / internal::CC_CUBIC_C_SCALE;
            if (cBytes == 0 || wMaxBytes == 0) return wMaxBytes;

            const uint64_t reduction = static_cast<uint64_t>(wMaxBytes)
                                     * (100 - internal::CC_LOSS_RETAIN_PERCENT) / 100;

            // K = cbrt(reduction / C) seconds. Taken in milliseconds, so the
            // cube root input is scaled by 1e9 and the result comes out already
            // in milliseconds, which keeps every intermediate inside 64 bits.
            const int64_t kMilli = static_cast<int64_t>(
                common::CubeRoot(reduction * 1000000000ull / cBytes));

            const int64_t elapsedMilli = static_cast<int64_t>(elapsedMicros / 1000);
            const int64_t offset       = elapsedMilli - kMilli;

            // C * offset^3, with offset in milliseconds, so the cube carries a
            // factor of 1e9 that divides back out. Clamped first, because a
            // cube of a large millisecond count overflows before the divide.
            constexpr int64_t OFFSET_LIMIT = 2000000;   // well past any real curve
            const int64_t bounded = offset >  OFFSET_LIMIT ?  OFFSET_LIMIT
                                  : offset < -OFFSET_LIMIT ? -OFFSET_LIMIT : offset;
            // One expression, divided once. Cubing three separately truncated
            // second counts is C * floor(t)^3, which is zero for any offset
            // under a second and flat in whole-second steps after it. With K
            // typically two to four seconds that resolved the entire concave
            // phase to a couple of values and left the curve contributing
            // nothing, so the controller was Reno wearing CUBIC's name.
            const int64_t growth = static_cast<int64_t>(cBytes)
                                 * bounded * bounded * bounded / 1000000000ll;

            const int64_t window = static_cast<int64_t>(wMaxBytes) + growth;
            if (window < 0) return 0;
            return static_cast<uint64_t>(window);
        }

        /** Where a straight line would have reached in the same time.

            CUBIC's curve is sized for windows that take many round trips to
            rebuild, so on a short path it climbs slower than Reno would. Taking
            whichever is further along means a short path is never punished for
            running a controller designed for long ones. */
        uint64_t RenoWindow(uint32_t wMaxBytes, uint64_t elapsedMicros,
                            uint32_t srttMicros) noexcept
        {
            if (srttMicros == 0) return 0;
            const uint64_t retained = static_cast<uint64_t>(wMaxBytes)
                                    * internal::CC_LOSS_RETAIN_PERCENT / 100;
            const uint64_t rounds   = elapsedMicros / srttMicros;
            const uint64_t perRound = static_cast<uint64_t>(internal::MAX_WIRE_PACKET_SIZE)
                                    * 3 * (100 - internal::CC_LOSS_RETAIN_PERCENT)
                                    / (100 + internal::CC_LOSS_RETAIN_PERCENT);
            return retained + rounds * perRound;
        }
    }

    void Socket::ApplyCongestion(Peer& peer, const CongestionDelta& delta,
                                  uint64_t nowMicros) noexcept
    {
        // Free what resolved, guarded so a bookkeeping drift can never wrap the
        // counter past zero into a huge value.
        peer.bytesInFlight -= delta.resolvedBytes <= peer.bytesInFlight
            ? delta.resolvedBytes : peer.bytesInFlight;
        peer.outstandingToPeer -= delta.resolvedPackets <= peer.outstandingToPeer
            ? delta.resolvedPackets : peer.outstandingToPeer;

        // The only place a measurement enters. The association gathered it
        // under its own lock and reported it here, because a flow may never
        // reach for a peer.
        if (delta.rttSampleMicros != 0)
        {
            const bool usable = peer.rtt.Sample(delta.rttSampleMicros,
                                                delta.ackDelayMicros, nowMicros);
            assert(usable && "round trip sample out of band: check what produced sentAtMicros");
            (void)usable;
        }

        // An answer of any kind means the peer is there, so the silence that
        // drives the doubling starts again.
        if (delta.ackedBytes != 0) peer.rtt.MarkAcked(nowMicros);

        // A probe went out and nothing came back with it. Past enough of them
        // the path is gone rather than busy, and a percentage of a number that
        // describes nothing is not worth taking, so the budget goes to the
        // floor. Short of that, the only cost is the probe itself.
        if (delta.sawProbe && delta.ackedBytes == 0)
        {
            const uint64_t base = peer.rtt.RetransmitTimeout(
                flows_.RetryIntervalMicros(), flows_.AckDelayMicros());
            if (peer.rtt.SilentForMicros(nowMicros)
                    > base * internal::PERSISTENT_CONGESTION_PROBES)
            {
                // The budget goes to the floor and slow start resumes from
                // there. The threshold is deliberately left where it was:
                // pinning it to the floor too would leave the peer crawling up
                // a curve from a two packet window, and a path that has just
                // come back deserves to find its capacity the fast way, exactly
                // as a new one would.
                // Only when it changes something. This fires on every resend
                // round through a stall, and the epoch is what bounds the
                // response to one trim per congestion event: walking it on a
                // collapse that has already happened eventually carries it
                // past the stamp on packets still in flight, and the signed
                // comparison then reads genuinely new losses as old ones and
                // stops trimming for them at all.
                if (peer.congestionBudget != minCongestionBudget_)
                {
                    peer.congestionBudget      = minCongestionBudget_;
                    peer.wMaxBytes             = minCongestionBudget_;
                    peer.congestionEpochMicros = nowMicros;
                    ++peer.congestionEpoch;
                }
            }
        }

        // Trim on loss, once per congestion event. The epoch is what makes that
        // exact: everything already in flight when we last reacted carries the
        // older number, so a burst losing ten packets is one reaction, while a
        // loss from a packet sent afterwards is genuinely new. A clock can only
        // approximate this, and it approximates worst right after a loss, when
        // the round trip it would measure against is least trustworthy.
        if (delta.sawLoss
            && static_cast<int8_t>(delta.lostEpoch - peer.congestionEpoch) >= 0)
        {
            // Loss says a packet died. Only the queue says why. A drop from a
            // full buffer arrives with the round trip already inflated, so the
            // estimate is high when congestion is real, and a drop from radio
            // noise or a faulty link arrives with the path empty. The two get
            // proportionate answers, because treating noise as congestion
            // settles the window at the AIMD equilibrium for the loss rate,
            // which on a lossy-but-idle link is a fraction of what it carries.
            const uint32_t minRtt = peer.rtt.MinRttMicros();
            uint32_t queueTarget = minRtt / internal::QUEUE_TARGET_DIVISOR;
            if (queueTarget < internal::QUEUE_TARGET_MIN_MICROS)
                queueTarget = internal::QUEUE_TARGET_MIN_MICROS;

            // The queue is one witness and the size of the bite is the other,
            // because the queue estimate goes blind in exactly one case: a
            // burst overflowing a shallow buffer. The packets that would have
            // carried the deep-queue reading are the ones the overflow
            // dropped, and the survivors met a buffer the pause just drained,
            // so the estimate reads empty while the budget runs away. Volume
            // is the physical tell between the two kinds of loss. Interference
            // takes a small fraction of packets at any send rate, while
            // overflow takes the whole excess: an acknowledgement declaring
            // half of what it resolves as lost is not describing radio noise.
            const uint64_t lostBytes = delta.lostDeclaredBytes;
            const bool bigBite =
                lostBytes * 2 >= lostBytes + delta.ackedBytes
                && lostBytes >= 3ull * internal::MAX_WIRE_PACKET_SIZE;

            // Any loss ends slow start, whatever the witnesses say. Doubling
            // is a probe for capacity and a loss during it is the probe
            // finding something: believing a false positive costs one
            // doubling, while disbelieving a true one lets the doubling run
            // hundreds of kilobytes past a shallow buffer and shreds every
            // resend behind it. Noise-classification is for avoidance, where
            // repeated trims compound, and every loss after this first one is
            // judged there.
            const bool inSlowStart = peer.congestionBudget < peer.slowStartThreshold;

            const bool congested = minRtt == 0
                                || peer.rtt.QueueMicros() > queueTarget
                                || bigBite
                                || inSlowStart;
            const uint32_t retain = congested ? internal::CC_LOSS_RETAIN_PERCENT
                                              : internal::CC_NOISE_RETAIN_PERCENT;

            // Captured before the cut. wMax is the curve's memory of where
            // trouble was found, and the whole shape depends on it naming the
            // window that was actually running when it appeared. Recording the
            // trimmed value instead puts the plateau below where we already
            // know the path reaches, and every event ratchets it down again.
            const uint32_t budgetAtLoss = peer.congestionBudget;

            uint32_t trimmed = static_cast<uint32_t>(
                static_cast<uint64_t>(peer.congestionBudget) * retain / 100);
            if (trimmed < minCongestionBudget_) trimmed = minCongestionBudget_;

            peer.congestionBudget = trimmed;

            // Two different clocks, and only one of them moves for noise. The
            // reaction epoch always advances, because it is what bounds the
            // response to one trim per event however many packets that event
            // took. The curve's anchor moves only when the queue said the
            // path's capacity was really reached: wMax is CUBIC's memory of
            // where trouble was, its curve is flattest exactly there, and
            // re-anchoring it on every noise loss pins the window to the
            // plateau, where regrowth per event loses to even a five percent
            // trim. A noise loss changes nothing about the path, so the curve
            // keeps climbing through it and the trim is the whole cost.
            if (congested)
            {
                peer.wMaxBytes             = budgetAtLoss;
                peer.slowStartThreshold    = trimmed;
                peer.congestionEpochMicros = nowMicros;
            }
            ++peer.congestionEpoch;
            return;   // nothing grows in the same breath as a reduction
        }

        if (delta.ackedBytes == 0) return;


        // The governor, and the only thing here reading a signal other than
        // loss. Whatever the curve wants, the window does not grow while a
        // queue is already standing in front of it: past that point more in
        // flight buys no throughput at all, and buys latency for everything
        // sharing the link. Without this the resting place is a full buffer.
        // Not applied below the opening window. A sender with a handful of
        // packets on the path cannot be the cause of a standing queue, and
        // holding it there would be worse than any queue it could build: after
        // a reduction the budget sits at the floor, and a governor that refuses
        // to let it leave freezes the peer at two packets for good.
        const uint32_t minRtt = peer.rtt.MinRttMicros();
        uint32_t target = minRtt / internal::QUEUE_TARGET_DIVISOR;
        if (target < internal::QUEUE_TARGET_MIN_MICROS)
            target = internal::QUEUE_TARGET_MIN_MICROS;
        if (minRtt != 0
            && peer.congestionBudget >= internal::CC_INITIAL_WINDOW_BYTES
            && peer.rtt.QueueMicros() > target)
        {
            // A queue found while still doubling means the bottleneck is here.
            // Stop and stay, rather than carrying on until the buffer overflows
            // and finding the same answer the expensive way.
            if (peer.congestionBudget < peer.slowStartThreshold)
            {
                peer.slowStartThreshold    = peer.congestionBudget;
                peer.wMaxBytes             = peer.congestionBudget;
                peer.congestionEpochMicros = nowMicros;
            }
            return;
        }

        if (peer.congestionBudget < peer.slowStartThreshold)
        {
            // Slow start: double per round trip. Saturating, so growth can
            // never wrap the budget, and capped at the ceiling because a
            // budget past what every window can hold is a stored burst.
            uint32_t grown = peer.congestionBudget + delta.ackedBytes;
            if (grown < peer.congestionBudget) grown = UINT32_MAX;
            if (grown > maxCongestionBudget_)  grown = maxCongestionBudget_;
            peer.congestionBudget = grown;
            return;
        }

        // Congestion avoidance. The curve is a function of time since the last
        // reduction, so it needs a starting point, and a peer that has never
        // lost anything takes the moment it left slow start.
        if (peer.congestionEpochMicros == 0)
        {
            peer.congestionEpochMicros = nowMicros;
            if (peer.wMaxBytes == 0) peer.wMaxBytes = peer.congestionBudget;
        }
        const uint64_t elapsed = nowMicros > peer.congestionEpochMicros
            ? nowMicros - peer.congestionEpochMicros : 0;

        const uint64_t cubic = CubicWindow(peer.wMaxBytes, elapsed);
        const uint64_t reno  = RenoWindow(peer.wMaxBytes, elapsed, peer.rtt.srttMicros);
        const uint64_t want  = cubic > reno ? cubic : reno;

        if (want > peer.congestionBudget)
        {
            // One packet per acknowledgement at most, so the curve is followed
            // rather than jumped to. A window that arrives in a single step is
            // a burst that the pacing then has to spread out again.
            const uint64_t step = want - peer.congestionBudget;
            const uint64_t capped = step > internal::MAX_WIRE_PACKET_SIZE
                ? internal::MAX_WIRE_PACKET_SIZE : step;
            uint32_t grown = peer.congestionBudget + static_cast<uint32_t>(capped);
            if (grown < peer.congestionBudget) grown = UINT32_MAX;
            if (grown > maxCongestionBudget_)  grown = maxCongestionBudget_;
            peer.congestionBudget = grown;
        }

        // The whole range, asserted at the one place the budget moves. A value
        // outside it is not a tuning problem, it is a bookkeeping bug, and a
        // clamp alone would hide it from the person who needs to find it.
        assert(peer.congestionBudget >= minCongestionBudget_
            && peer.congestionBudget <= maxCongestionBudget_);
    }
}
