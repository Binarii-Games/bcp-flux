#include <flux/socket/socket.h>

#include <cassert>

#include <flux/internal/congestion_curve.h>
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

    A deadline is a guess about a path nobody can see, and it is wrong most
    often exactly when the path is worst, so for a reliable flow it buys a probe
    and nothing more: the acknowledgement that comes back is what says which
    packets are missing. The exception is an unreliable flow, whose packets are
    never resent. There the deadline is not a guess about whether the packet
    might still arrive, it is the moment the packet stops existing, so it is the
    only loss signal that flow will ever produce and it is taken.

    Starvation is the third judgement, and it protects the delay response
    from neighbours that do not share it. A sender holding back for a queue a
    neighbour keeps refilling ends at a few packets of budget on a link with
    room for a hundred times that. A budget pinned that low with the queue
    standing and acknowledgements still arriving is read as starvation rather
    than congestion, and the answer is to stop treating that queue as this
    sender's own: the level found at the verdict becomes the bound, the
    budget regrows at ramp speed underneath it, and nothing pushes above it,
    so the recovery competes for queue space that already exists rather than
    adding more.

    It lives beside the socket rather than in the flow table because the budget
    is the peer's and not any one flow's. The gate that spends it is CanSend, in
    the flow table, which is where the packet being admitted is. */

namespace bcp::flux
{
    namespace
    {
        /** One ramp step: the budget grows by what was acknowledged,
            saturating, capped at the ceiling. Never zero, so rounding can
            never stall the ramp. Slow start and the starved regrowth both
            climb this way, and they climb the same way on purpose: a starved
            peer recovering slower than a new one would never catch the gap
            it is recovering into. */
        uint32_t RampStep(uint32_t budget, uint32_t ackedBytes,
                          uint32_t ceiling) noexcept
        {
            uint32_t step = ackedBytes;
            if (step == 0) step = 1;
            uint32_t grown = budget + step;
            if (grown < budget)  grown = UINT32_MAX;
            if (grown > ceiling) grown = ceiling;
            return grown;
        }

        /** The queue as the starvation verdict measures it: against the
            minimum round trip frozen when the verdict was reached, not the
            live one. The live minimum is remembered through a rotating
            window, and a queue that stands longer than the window fills
            every bucket with queued samples, so the live reading deflates
            under exactly the queue this mode exists to survive. */
        uint32_t StarvedQueueMicros(const Peer& peer) noexcept
        {
            return peer.rtt.srttMicros > peer.starvedMinRttMicros
                ? peer.rtt.srttMicros - peer.starvedMinRttMicros : 0;
        }

        /** The same queue as the newest sample saw it. The smoothed figure
            lags a full round trip, and a budget doubling per round trip can
            put hundreds of kilobytes past the bound in the time the lag
            hides. The ramp and the loss witness watch whichever of the two
            readings is worse, exactly as slow start watches the newest
            sample for its sighting. */
        uint32_t StarvedWorstQueueMicros(const Peer& peer) noexcept
        {
            const uint32_t latest = peer.rtt.latestMicros > peer.starvedMinRttMicros
                ? peer.rtt.latestMicros - peer.starvedMinRttMicros : 0;
            const uint32_t smoothed = StarvedQueueMicros(peer);
            return latest > smoothed ? latest : smoothed;
        }

        /** A confirmation window in round trips, floored in absolute time,
            because a count of round trips alone is milliseconds on a short
            path and the things it has to see past are not. */
        uint64_t ConfirmWindowMicros(uint32_t roundTripMicros, uint32_t rounds,
                                     uint32_t floorMicros) noexcept
        {
            const uint64_t spanned =
                static_cast<uint64_t>(rounds) * roundTripMicros;
            return spanned > floorMicros ? spanned : floorMicros;
        }
    }

    void Socket::AssertBudgetInRange(const Peer& peer) const noexcept
    {
        // A value outside the range is not a tuning problem, it is a
        // bookkeeping bug, and a silent clamp would hide it from the person who
        // has to find it.
        assert(peer.congestionBudget >= minCongestionBudget_
            && peer.congestionBudget <= maxCongestionBudget_);
        (void)peer;
    }

    void Socket::ApplyCongestion(Peer& peer, const CongestionDelta& delta,
                                  uint64_t nowMicros) noexcept
    {
        // Captured before the free below, because the question a loss raises
        // is how much was on the path when it happened, not how much is left
        // now that this acknowledgement has cleared some of it.
        const uint32_t inFlightAtEvent = peer.bytesInFlight;

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

        // What arrived is what the path demonstrably carries, and what did not
        // is what it costs to use. Folded on every pass rather than only on a
        // loss, since both have to be built while things are going well to be
        // worth anything when they are not.
        peer.delivery.Sample(delta.ackedBytes, delta.lostDeclaredBytes, nowMicros);

        // The starvation verdict. The readings are taken here, after the
        // sample fold, so every branch below judges the same picture. Entry
        // needs all three conditions continuously through the confirm
        // window: the queue standing, the budget pinned under the threshold,
        // and the verdict itself taken only on an acknowledgement, because a
        // starved peer is one being outcompeted on a live path, not one
        // whose path has died. Losses do not reset the candidate clock. They
        // are what starvation looks like, not evidence against it.
        const uint32_t pathMinRtt = peer.rtt.MinRttMicros();
        const uint32_t queueNow   = peer.rtt.QueueMicros();
        const bool queueOverTarget = pathMinRtt != 0
            && queueNow > internal::QueueTargetMicros(pathMinRtt);

        if (peer.starvedSinceMicros == 0)
        {
            // An episode that ended longer than the re-entry window ago is
            // over: the kept references describe a contention that stopped,
            // and the next verdict earns a fresh capture.
            if (peer.starvedExitedAtMicros != 0
                && nowMicros > peer.starvedExitedAtMicros
                       + internal::CC_STARVED_REENTRY_WINDOW_MICROS)
            {
                peer.starvedExitedAtMicros = 0;
                peer.starvedQueueCapMicros = 0;
                peer.starvedMinRttMicros   = 0;
            }

            const bool starvedNow = queueOverTarget
                && peer.congestionBudget <= internal::CC_STARVED_BUDGET_BYTES;
            if (!starvedNow)
                peer.starvedCandidateSinceMicros = 0;
            else if (delta.ackedBytes != 0 && peer.starvedExitedAtMicros != 0)
            {
                // A relapse inside the window: the exit was the competitor
                // pausing, not leaving. Re-engage at once with the kept
                // references. Confirming again costs a second of starvation
                // per cycle, and re-capturing mid-contention would freeze a
                // minimum the standing queue has already corrupted.
                peer.starvedSinceMicros          = nowMicros;
                peer.starvedExitedAtMicros       = 0;
                peer.starvedClearSinceMicros     = 0;
                peer.starvedCandidateSinceMicros = 0;
                ++peer.starvedEpisodes;
            }
            else if (peer.starvedCandidateSinceMicros == 0)
                peer.starvedCandidateSinceMicros = nowMicros;
            else if (delta.ackedBytes != 0)
            {
                const uint64_t held = nowMicros > peer.starvedCandidateSinceMicros
                    ? nowMicros - peer.starvedCandidateSinceMicros : 0;
                const uint64_t confirm = ConfirmWindowMicros(
                    peer.rtt.RoundTripOr(flows_.RetryIntervalMicros()),
                    internal::CC_STARVED_CONFIRM_ROUNDS,
                    internal::CC_STARVED_CONFIRM_MIN_MICROS);
                if (held >= confirm)
                {
                    peer.starvedSinceMicros          = nowMicros;
                    peer.starvedQueueCapMicros       = queueNow
                        + internal::QueueTargetMicros(pathMinRtt)
                            / internal::CC_STARVED_CAP_SLACK_DIVISOR;
                    peer.starvedMinRttMicros         = pathMinRtt;
                    peer.starvedClearSinceMicros     = 0;
                    peer.starvedCandidateSinceMicros = 0;
                    ++peer.starvedEpisodes;
                }
            }
        }

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
                    peer.congestionBudget          = minCongestionBudget_;
                    peer.wMaxBytes                 = minCongestionBudget_;
                    peer.congestionEpochMicros     = nowMicros;
                    peer.slowStartQueueSinceMicros = 0;
                    ++peer.congestionEpoch;
                }
                // A silence this long is a dead path, and the starvation
                // verdict describes a live one, so whatever it was measuring
                // no longer exists. Everything is forgotten, the kept
                // references included.
                peer.starvedCandidateSinceMicros = 0;
                peer.starvedSinceMicros          = 0;
                peer.starvedClearSinceMicros     = 0;
                peer.starvedExitedAtMicros       = 0;
                peer.starvedQueueCapMicros       = 0;
                peer.starvedMinRttMicros         = 0;
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

            // The queue is one witness and the size of the bite is the other,
            // because the queue estimate goes blind in exactly one case: a
            // burst overflowing a shallow buffer. The packets that would have
            // carried the deep-queue reading are the ones the overflow
            // dropped, and the survivors met a buffer the pause just drained,
            // so the estimate reads empty while the budget runs away.
            //
            // Volume alone cannot finish the job, because a burst of
            // interference is byte for byte the same event: a run of losses
            // with the queue reading empty. The two are indistinguishable from
            // these two signals, so the bite carries a precondition rather
            // than a tuning. An overflow is self-inflicted, so it can only
            // happen to a sender near what the path carries, while
            // interference takes packets at any rate. Measured on a link
            // losing two percent in bursts of twenty: forty four of eighty
            // trims were charged as overflow while the sender sat at a third
            // of capacity, which is a rate that cannot overflow anything, and
            // the full cut each time held it there for the whole transfer.
            const uint64_t lostBytes = delta.lostDeclaredBytes;
            const bool bigBite =
                lostBytes * 2 >= lostBytes + delta.ackedBytes
                && lostBytes >= 3ull * internal::MAX_WIRE_PACKET_SIZE
                && peer.delivery.CouldOverflow(minRtt, inFlightAtEvent);

            // A loss during slow start is judged by the same two witnesses as
            // any other. It once ended slow start unconditionally, priced as
            // one wasted doubling if the loss turned out to be noise. The
            // measured price on a link with one percent random loss was the
            // whole transfer: the first loss lands about a hundred packets
            // in, while the ramp is still small, and anchoring the curve at
            // that window held the budget to a third of the path for seven
            // seconds. The overshoot the old rule guarded against is what the
            // witnesses here already catch, the queue for a deep buffer
            // filling and the bite for a shallow one overflowing, and the
            // ramp itself now ends on the delay sighting rather than waiting
            // for loss to be the messenger.
            // A link losing whole percentages steadily is describing itself,
            // not asking this sender to slow down, so below the tolerance the
            // queue is the entire congestion detector and the bite witness
            // has no vote. That is not a loosening: the queue sees a
            // bottleneck filling before anything is dropped, which is earlier
            // and more specific than loss ever is. The witness regains its
            // vote the moment the link loses more than a congested one needs
            // to, which is where a shallow buffer overflowing lands.
            const bool lossAboveTolerance =
                peer.delivery.LossPercent() > internal::CC_LOSS_TOLERANCE_PERCENT;
            // While the starvation verdict holds, the frozen level replaces
            // the target as the queue witness. The queue standing over the
            // target is the very condition the verdict was reached under, so
            // judged against the target every loss would read as congestion
            // and the trims would hold the peer exactly where the starver
            // put it. Against the frozen level the witness still has teeth:
            // a loss with the queue pushed past it is this sender growing
            // into space that was never there, and takes the full cut.
            const bool queueStanding = peer.starvedSinceMicros != 0
                ? StarvedWorstQueueMicros(peer) > peer.starvedQueueCapMicros
                : minRtt != 0
                    && peer.rtt.QueueMicros() > internal::QueueTargetMicros(minRtt);

            const bool congested = minRtt == 0
                                || queueStanding
                                || (bigBite && lossAboveTolerance);
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

            peer.congestionBudget          = trimmed;
            peer.slowStartQueueSinceMicros = 0;

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
            AssertBudgetInRange(peer);
            return;   // nothing grows in the same breath as a reduction
        }

        if (delta.ackedBytes == 0) return;

        // Recovery from starvation, in place of the ordinary branches below.
        // The exit watches the ordinary target: a queue that holds under it
        // through the exit window has genuinely drained, which means the
        // competitor left, and normal manners resume from wherever the
        // budget stands. A recovered share is deliberately not the exit,
        // because a competitor still present starves it again at once.
        if (peer.starvedSinceMicros != 0)
        {
            // Exit and bound both read the queue against the frozen
            // minimum, because the live one deflates under a queue that
            // outlives its window and would read a still-occupied path as
            // drained.
            const uint32_t starvedQueue = StarvedQueueMicros(peer);
            if (starvedQueue <= internal::QueueTargetMicros(peer.starvedMinRttMicros))
            {
                if (peer.starvedClearSinceMicros == 0)
                    peer.starvedClearSinceMicros = nowMicros;
                else
                {
                    const uint64_t clearHeld = nowMicros > peer.starvedClearSinceMicros
                        ? nowMicros - peer.starvedClearSinceMicros : 0;
                    const uint64_t confirm = ConfirmWindowMicros(
                        peer.rtt.RoundTripOr(flows_.RetryIntervalMicros()),
                        internal::CC_STARVED_EXIT_ROUNDS,
                        internal::CC_STARVED_EXIT_MIN_MICROS);
                    if (clearHeld >= confirm)
                    {
                        // The references are kept: if this exit was a
                        // competitor pausing rather than leaving, the
                        // relapse re-engages with them inside the re-entry
                        // window, and only a path clean past it forgets.
                        peer.starvedSinceMicros        = 0;
                        peer.starvedExitedAtMicros     = nowMicros;
                        peer.starvedClearSinceMicros   = 0;
                        peer.slowStartThreshold        = peer.congestionBudget;
                        peer.wMaxBytes                 = peer.congestionBudget;
                        peer.congestionEpochMicros     = nowMicros;
                        peer.slowStartQueueSinceMicros = 0;
                        AssertBudgetInRange(peer);
                        return;
                    }
                }
            }
            else peer.starvedClearSinceMicros = 0;

            // The frozen level is the bound: at or under it the budget
            // climbs at ramp speed, over it the budget holds. Speed matters
            // here. A competitor that drains the queue to probe releases the
            // path for a fraction of a second, and a recovery slower than
            // that window never recovers at all. The gate reads the worse of
            // the smoothed and newest samples, so the climb stops a round
            // trip sooner than the smoothed figure alone could say.
            if (StarvedWorstQueueMicros(peer) > peer.starvedQueueCapMicros) return;

            peer.congestionBudget = RampStep(peer.congestionBudget,
                                             delta.ackedBytes,
                                             maxCongestionBudget_);
            AssertBudgetInRange(peer);
            return;
        }

        // The queue readings the branches below act on. Not taken below the
        // opening window. A sender with a handful of packets on the path
        // cannot be the cause of a standing queue, and after a reduction the
        // budget sits at the floor, so acting on a reading there would freeze
        // the peer at two packets for good.
        const uint32_t queueMinRtt = peer.rtt.MinRttMicros();
        const bool     signalLive  = queueMinRtt != 0
            && peer.congestionBudget >= internal::CC_INITIAL_WINDOW_BYTES;
        const uint32_t queueTarget = signalLive
            ? internal::QueueTargetMicros(queueMinRtt) : 0;
        const bool queueStanding  = signalLive
            && peer.rtt.QueueMicros() > queueTarget;
        const bool latestStanding = signalLive
            && peer.rtt.LatestQueueMicros() > queueTarget;

        if (peer.congestionBudget < peer.slowStartThreshold)
        {
            // Slow start doubles while the path reads clean, because a flat
            // fraction of a doubling taxes every link to protect the few that
            // need protecting. The sighting that stops it comes from the
            // newest sample, which crosses the moment a queue forms, where
            // the smoothed figure lags a full doubling behind. The ramp then
            // holds flat while the smoothed figure is given time to agree:
            // one sample can be jitter or a coalesced acknowledgement, and
            // ending the ramp on it strands the budget far below what the
            // path carries. Growing through that check instead of holding
            // was measured overflowing the buffer before the verdict could
            // arrive. A queue that outlives the check with the budget flat
            // is this sender's own, and slow start ends where it stands, one
            // buffer overflow earlier than a loss would have ended it.
            if (peer.slowStartQueueSinceMicros == 0)
            {
                if (latestStanding)
                {
                    peer.slowStartQueueSinceMicros = nowMicros;
                    return;
                }
            }
            else if (!latestStanding && !queueStanding)
            {
                // Both readings clean again: the sighting was noise, the
                // doubling resumes below. Released only when the smoothed
                // figure agrees, because the newest sample alone dips once
                // per round on a real queue, and resuming on each dip climbs
                // straight past the ceiling in steps.
                peer.slowStartQueueSinceMicros = 0;
            }
            else
            {
                const uint64_t held = nowMicros > peer.slowStartQueueSinceMicros
                    ? nowMicros - peer.slowStartQueueSinceMicros : 0;
                const uint64_t confirm =
                    static_cast<uint64_t>(internal::CC_SLOW_START_CONFIRM_ROUNDS)
                    * peer.rtt.RoundTripOr(flows_.RetryIntervalMicros());
                if (held >= confirm)
                {
                    peer.slowStartThreshold        = peer.congestionBudget;
                    peer.wMaxBytes                 = peer.congestionBudget;
                    peer.congestionEpochMicros     = nowMicros;
                    peer.slowStartQueueSinceMicros = 0;
                    AssertBudgetInRange(peer);
                }
                return;   // flat while confirming, and nothing grows the
                          // moment slow start ends
            }

            peer.congestionBudget = RampStep(peer.congestionBudget,
                                             delta.ackedBytes,
                                             maxCongestionBudget_);
            AssertBudgetInRange(peer);
            return;
        }

        // The governor, and the only thing past slow start reading a signal
        // other than loss. Whatever the curve wants, the window does not grow
        // while a queue is already standing in front of it: past that point
        // more in flight buys no throughput at all, and buys latency for
        // everything sharing the link. Without this the resting place is a
        // full buffer.
        if (queueStanding) return;

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

        const uint64_t cubic = internal::CubicWindow(peer.wMaxBytes, elapsed);
        const uint64_t reno  = internal::RenoWindow(peer.wMaxBytes, elapsed, peer.rtt.srttMicros);
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

        AssertBudgetInRange(peer);
    }
}
