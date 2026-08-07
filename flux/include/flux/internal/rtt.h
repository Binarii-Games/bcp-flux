#pragma once

#include <cstdint>

#include <flux/internal/constants.h>

namespace bcp::flux::internal
{
    /** How long the path to one peer takes, and how long to wait before calling
        a packet lost. A peer holds one of these and nothing else holds any.

        The round trip belongs to the path, and the path is the peer. Every flow
        to that peer crosses the same wire and measures the same thing, so an
        estimate per association was the same measurement taken several times
        over, each copy learning it separately and none of them sharing what it
        learned. A second flow to a known peer now starts with the timeout the
        first one paid to discover, rather than from the Config fallback.

        One place takes a measurement in and one place turns it into a deadline.
        Nothing outside this struct writes any of these fields. */
    struct RttEstimate
    {
        uint32_t srttMicros;    ///< smoothed round trip, 0 until the first usable sample
        uint32_t rttvarMicros;  ///< mean deviation, what separates a deadline from the average

        /** The longest this peer has recently admitted to holding an
            acknowledgement, from the figure it reports in every one. The
            deadline has to allow for it, because a sample has the hold
            subtracted out, so the smoothed value measures the path while the
            wait for an answer is the path plus the hold.

            Peak with decay: it rises the instant a longer hold is seen and
            falls slowly, so one stalled moment on the remote cannot pin the
            deadline high for the rest of the connection. */
        uint32_t peerAckDelayMicros;

        void Reset() noexcept
        {
            srttMicros         = 0;
            rttvarMicros       = 0;
            peerAckDelayMicros = 0;
        }

        /** Folds one measurement in: the round trip, and how long the far side
            held the acknowledgement that produced it.

            @return false, changing nothing, when the round trip is zero or past
                    RTT_SAMPLE_MAX_MICROS. A figure that large did not come from
                    the network, it came from subtracting something that was
                    never a timestamp, and one of them poisons every decision
                    built on the smoothed value afterwards. */
        [[nodiscard]] bool Sample(uint64_t roundTripMicros, uint32_t heldMicros) noexcept
        {
            if (roundTripMicros == 0 || roundTripMicros > RTT_SAMPLE_MAX_MICROS)
                return false;

            const uint32_t sample = static_cast<uint32_t>(roundTripMicros);

            if (srttMicros == 0)
            {
                srttMicros   = sample;
                rttvarMicros = sample / 2;
            }
            else
            {
                // Jacobson/Karels. The deviation is folded before the average,
                // so it measures the gap against the average this sample is
                // being judged by rather than the one it has already moved.
                const uint32_t diff = srttMicros > sample
                    ? srttMicros - sample : sample - srttMicros;
                rttvarMicros = (rttvarMicros * 3 + diff) / 4;
                srttMicros   = (srttMicros * 7 + sample) / 8;
            }

            peerAckDelayMicros = heldMicros > peerAckDelayMicros
                ? heldMicros
                : (peerAckDelayMicros * 7 + heldMicros) / 8;
            return true;
        }

        /** One round trip, or the caller's stand-in when nothing has been
            measured yet. Everything that needs the duration of a round trip
            asks here, so what happens before the first sample is decided once
            rather than at each site that has to cope with it. */
        [[nodiscard]] uint32_t RoundTripOr(uint32_t fallbackMicros) const noexcept
        {
            return srttMicros != 0 ? srttMicros : fallbackMicros;
        }

        /** How long to wait for an acknowledgement before treating the packet
            as lost.

            Three terms, each covering a different way an answer can be later
            than average. The smoothed round trip is the path. The variance
            covers the path moving, with a lower bound so a steady path cannot
            shrink the allowance to nothing, which once left a 256 microsecond
            margin on a 40 millisecond path and declared 582 losses in eight
            seconds with nothing dropped. The hold covers the far side waiting
            for a second packet before it answers.

            `ackCadenceMicros` is the interval this side runs its own
            acknowledgements at, used as the lower bound on the hold. The
            reported figure alone is not enough: it describes the newest
            sequence in an acknowledgement, which is the one that waited least,
            so in a stream of full packets it reads near zero while the older
            sequences in the same batch waited far longer, and it is those the
            deadline is measured against. */
        [[nodiscard]] uint64_t RetransmitTimeout(uint32_t fallbackMicros,
                                                 uint32_t ackCadenceMicros) const noexcept
        {
            uint64_t variance = 4ull * rttvarMicros;
            if (variance < RTO_VARIANCE_MIN_MICROS) variance = RTO_VARIANCE_MIN_MICROS;

            uint64_t hold = ackCadenceMicros;
            if (peerAckDelayMicros > hold) hold = peerAckDelayMicros;

            const uint64_t rto = RoundTripOr(fallbackMicros) + variance + hold;
            if (rto < 1000) return 1000;
            return rto > RTO_MAX_MICROS ? RTO_MAX_MICROS : rto;
        }
    };
}
