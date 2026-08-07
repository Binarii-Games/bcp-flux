#include <flux/socket/socket.h>

#include <flux/internal/constants.h>

/** Congestion control: how much a peer may keep on the path, and how that
    ceiling moves.

    Additive increase, multiplicative decrease. The budget doubles per round
    trip below the slow-start threshold and grows by roughly one packet per
    round trip above it, and a loss trims it to a percentage of itself but never
    below the configured floor. A loss reacts at most once per round trip, so a
    burst that loses ten packets is one trim rather than ten.

    It lives beside the socket rather than in the flow table because the budget
    is the peer's and not any one flow's. The gate that spends it is CanSend, in
    the flow table, which is where the packet being admitted is. */

namespace bcp::flux
{
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
            const bool usable = peer.rtt.Sample(delta.rttSampleMicros, delta.ackDelayMicros);
            assert(usable && "round trip sample out of band: check what produced sentAtMicros");
            (void)usable;
        }

        // Grow on acknowledged bytes: double the budget per round-trip below the
        // threshold, one packet per round-trip at or above it. Saturating, so
        // growth can never wrap the budget.
        if (delta.ackedBytes != 0)
        {
            uint32_t growth;
            if (peer.congestionBudget < peer.slowStartThreshold)
                growth = delta.ackedBytes;
            else
            {
                growth = static_cast<uint32_t>(
                    static_cast<uint64_t>(internal::MAX_WIRE_PACKET_SIZE)
                    * delta.ackedBytes / peer.congestionBudget);
                if (growth == 0) growth = 1;
            }
            peer.congestionBudget = peer.congestionBudget + growth < peer.congestionBudget
                ? UINT32_MAX : peer.congestionBudget + growth;
        }

        // Trim on loss, at most once per round-trip, never below the floor. The
        // threshold follows the trimmed budget, so growth resumes as the
        // one-packet-per-round-trip crawl rather than doubling.
        if (delta.sawLoss)
        {
            const uint32_t interval = peer.rtt.RoundTripOr(flows_.RetryIntervalMicros());
            if (peer.lastLossReactionMicros == 0
                || nowMicros - peer.lastLossReactionMicros >= interval)
            {
                uint32_t trimmed = static_cast<uint32_t>(
                    static_cast<uint64_t>(peer.congestionBudget)
                    * internal::CC_LOSS_RETAIN_PERCENT / 100);
                if (trimmed < minCongestionBudget_) trimmed = minCongestionBudget_;
                peer.congestionBudget       = trimmed;
                peer.slowStartThreshold     = trimmed;
                peer.lastLossReactionMicros = nowMicros;
            }
        }
    }
}
