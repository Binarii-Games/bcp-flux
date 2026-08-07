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

        /** The newest sample, unsmoothed. The time-threshold rule compares
            against the larger of this and the average, because a path that has
            just slowed has not moved the average yet and judging by the average
            alone would call packets lost that are merely late. */
        uint32_t latestMicros;

        /** The lowest round trip seen recently, which is the path with nothing
            queued in front of it. Everything above it is queue, and that
            subtraction is the only way to see a queue forming before it
            overflows.

            Buckets rather than one number, because a single minimum can only
            ever fall. If the route changes and the path genuinely lengthens, a
            lifetime minimum stays at a value the path can no longer reach and
            reports queue that does not exist, permanently. The buckets rotate,
            so the memory ages out instead of being stuck or reset with a jump,
            and the answer is the smallest of the ones still live. */
        uint32_t minBucketsMicros[MIN_RTT_BUCKETS];
        uint64_t minRotatedAtMicros;

        /** When this peer last acknowledged something new. How long it has been
            silent drives both the doubling of the timeout and the decision that
            the path is gone rather than busy.

            Derived from one timestamp rather than counted. A counter has to be
            incremented from somewhere, and the only thing that runs often
            enough is the retransmit tick, which fires far more often than a
            timeout elapses. Counting there reads three unanswered probes out of
            one and collapses the budget on a link that is merely lossy. */
        uint64_t lastAckedAtMicros;

        void Reset() noexcept
        {
            srttMicros         = 0;
            rttvarMicros       = 0;
            peerAckDelayMicros = 0;
            latestMicros       = 0;
            minRotatedAtMicros = 0;
            lastAckedAtMicros  = 0;
            for (uint32_t i = 0; i < MIN_RTT_BUCKETS; ++i)
                minBucketsMicros[i] = 0;   // 0 reads as empty, never as a measurement
        }

        /** The lowest round trip still remembered, or 0 before the first
            sample. */
        [[nodiscard]] uint32_t MinRttMicros() const noexcept
        {
            uint32_t lowest = 0;
            for (uint32_t i = 0; i < MIN_RTT_BUCKETS; ++i)
            {
                const uint32_t bucket = minBucketsMicros[i];
                if (bucket != 0 && (lowest == 0 || bucket < lowest)) lowest = bucket;
            }
            return lowest;
        }

        /** How much of the current round trip is packets waiting in a queue
            rather than the path itself. Zero before there is anything to
            compare, and floored, since a sample below the remembered minimum
            means the minimum is about to move rather than that the queue is
            negative. */
        [[nodiscard]] uint32_t QueueMicros() const noexcept
        {
            const uint32_t lowest = MinRttMicros();
            if (lowest == 0 || srttMicros <= lowest) return 0;
            return srttMicros - lowest;
        }

        /** The peer answered. Resets the silence whether or not the
            acknowledgement also yielded a usable round trip, because a reply
            Karn's rule refuses is still proof the peer is there. */
        void MarkAcked(uint64_t nowMicros) noexcept { lastAckedAtMicros = nowMicros; }

        /** How long since this peer last said anything. */
        [[nodiscard]] uint64_t SilentForMicros(uint64_t nowMicros) const noexcept
        {
            if (lastAckedAtMicros == 0 || nowMicros <= lastAckedAtMicros) return 0;
            return nowMicros - lastAckedAtMicros;
        }

        /** Folds one measurement in: the round trip, and how long the far side
            held the acknowledgement that produced it.

            @return false, changing nothing, when the round trip is zero or past
                    RTT_SAMPLE_MAX_MICROS. A figure that large did not come from
                    the network, it came from subtracting something that was
                    never a timestamp, and one of them poisons every decision
                    built on the smoothed value afterwards. */
        [[nodiscard]] bool Sample(uint64_t roundTripMicros, uint32_t heldMicros,
                                  uint64_t nowMicros) noexcept
        {
            if (roundTripMicros == 0 || roundTripMicros > RTT_SAMPLE_MAX_MICROS)
                return false;

            const uint32_t sample = static_cast<uint32_t>(roundTripMicros);
            latestMicros = sample;

            // Rotate first, so a sample lands in a bucket whose age is known.
            // A long idle gap retires every bucket rather than looping, since
            // nothing older than the window may survive it.
            if (minRotatedAtMicros == 0) minRotatedAtMicros = nowMicros;
            uint64_t elapsed = nowMicros > minRotatedAtMicros
                ? nowMicros - minRotatedAtMicros : 0;
            while (elapsed >= MIN_RTT_BUCKET_MICROS)
            {
                for (uint32_t i = MIN_RTT_BUCKETS - 1; i > 0; --i)
                    minBucketsMicros[i] = minBucketsMicros[i - 1];
                minBucketsMicros[0] = 0;
                minRotatedAtMicros += MIN_RTT_BUCKET_MICROS;
                elapsed            -= MIN_RTT_BUCKET_MICROS;
            }
            if (minBucketsMicros[0] == 0 || sample < minBucketsMicros[0])
                minBucketsMicros[0] = sample;

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
                                                 uint32_t ackCadenceMicros,
                                                 uint64_t nowMicros = 0) const noexcept
        {
            uint64_t variance = 4ull * rttvarMicros;
            if (variance < RTO_VARIANCE_MIN_MICROS) variance = RTO_VARIANCE_MIN_MICROS;

            uint64_t hold = ackCadenceMicros;
            if (peerAckDelayMicros > hold) hold = peerAckDelayMicros;

            uint64_t rto = RoundTripOr(fallbackMicros) + variance + hold;

            // One doubling per whole timeout that has elapsed in silence.
            // Without it a peer that has gone quiet is asked again at the same
            // interval forever, which turns a bad moment into a flood at
            // exactly the wrong time. Capped so it cannot outrun the ceiling in
            // a single step, and it unwinds on its own the moment an
            // acknowledgement resets the silence.
            const uint64_t silent = SilentForMicros(nowMicros);
            for (uint32_t shift = 0; shift < RTO_MAX_BACKOFF_SHIFT && silent > rto; ++shift)
                rto <<= 1;

            if (rto < 1000) return 1000;
            return rto > RTO_MAX_MICROS ? RTO_MAX_MICROS : rto;
        }

        /** How long a packet may be outstanding, once something above it has
            arrived, before the gap is treated as loss rather than reordering.

            Against the larger of the newest sample and the average, because a
            path that has just slowed has not moved the average yet. Nine
            eighths is the spare eighth that separates a reordered packet from a
            lost one, and it is the figure RFC 9002 uses. */
        [[nodiscard]] uint64_t LossDelayMicros() const noexcept
        {
            const uint64_t base = latestMicros > srttMicros ? latestMicros : srttMicros;
            const uint64_t delay = base + base / 8;
            return delay < RTO_VARIANCE_MIN_MICROS ? RTO_VARIANCE_MIN_MICROS : delay;
        }
    };
}
