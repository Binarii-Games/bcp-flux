#pragma once

#include <cstdint>

#include <flux/internal/constants.h>

namespace bcp::flux::internal
{
    /** What this path carries and what it drops, and from those how much may
        be in flight at once and how much loss is simply this link's nature. A
        peer holds one of these and nothing else holds any.

        It exists to answer one question the other signals cannot: whether this
        sender was going fast enough for a loss to be its own fault. An
        overflowing buffer is self-inflicted by definition, so it can only
        happen at or above what the path carries, while interference takes
        packets at any rate. Without that check a burst of interference and a
        burst from an overflow are the same event, because both arrive as a run
        of losses with the queue reading empty: the packets that would have
        shown the deep queue are exactly the ones that went missing.

        Buckets holding a maximum, mirroring the minimum-round-trip buckets
        next door and for the same reason. A single figure that only ever rises
        would keep a rate the path reached once and cannot reach again, and one
        that follows every dip would collapse during the very burst it is meant
        to judge. Rotating buckets age the memory out instead. */
    struct DeliveryEstimate
    {
        /** Acknowledged bytes per bucket, newest first. A bucket is a fixed
            span, so the largest byte count is also the largest rate and the
            division happens once, at the end. */
        uint32_t bucketBytes[DELIVERY_BUCKETS];
        /** Bytes declared lost in the same spans, so the ratio between the two
            is taken over one window and needs no second clock. */
        uint32_t lostBytes[DELIVERY_BUCKETS];
        uint64_t rotatedAtMicros;
        bool     everComplete;   ///< a bucket has retired, so a rate is known

        void Reset() noexcept
        {
            for (uint32_t i = 0; i < DELIVERY_BUCKETS; ++i)
            {
                bucketBytes[i] = 0;
                lostBytes[i]   = 0;
            }
            rotatedAtMicros = 0;
            everComplete    = false;
        }

        /** Folds acknowledged bytes in and ages the buckets. Called wherever
            the congestion feedback is applied, which is the one place that
            knows what an acknowledgement resolved. */
        void Sample(uint32_t ackedBytes, uint64_t lostDeclaredBytes,
                    uint64_t nowMicros) noexcept
        {
            if (rotatedAtMicros == 0) rotatedAtMicros = nowMicros;

            uint64_t elapsed = nowMicros > rotatedAtMicros
                ? nowMicros - rotatedAtMicros : 0;
            while (elapsed >= DELIVERY_BUCKET_MICROS)
            {
                for (uint32_t i = DELIVERY_BUCKETS - 1; i > 0; --i)
                {
                    bucketBytes[i] = bucketBytes[i - 1];
                    lostBytes[i]   = lostBytes[i - 1];
                }
                bucketBytes[0]   = 0;
                lostBytes[0]     = 0;
                rotatedAtMicros += DELIVERY_BUCKET_MICROS;
                elapsed         -= DELIVERY_BUCKET_MICROS;
                everComplete     = true;
            }

            const uint64_t grown =
                static_cast<uint64_t>(bucketBytes[0]) + ackedBytes;
            bucketBytes[0] = grown > UINT32_MAX
                ? UINT32_MAX : static_cast<uint32_t>(grown);

            const uint64_t lost =
                static_cast<uint64_t>(lostBytes[0]) + lostDeclaredBytes;
            lostBytes[0] = lost > UINT32_MAX
                ? UINT32_MAX : static_cast<uint32_t>(lost);
        }

        /** What share of this path's recent traffic did not arrive, as a
            percentage of everything that resolved either way. 0 before a
            bucket has retired, which reads as "not yet known".

            Taken over the whole window rather than per event, because a single
            acknowledgement resolving one loss and one delivery reports fifty
            percent and describes nothing. */
        [[nodiscard]] uint32_t LossPercent() const noexcept
        {
            if (!everComplete) return 0;
            uint64_t delivered = 0;
            uint64_t lost      = 0;
            for (uint32_t i = 1; i < DELIVERY_BUCKETS; ++i)
            {
                delivered += bucketBytes[i];
                lost      += lostBytes[i];
            }
            const uint64_t resolved = delivered + lost;
            if (resolved == 0) return 0;
            return static_cast<uint32_t>(lost * 100 / resolved);
        }

        /** The most this path was seen to carry in one bucket, or 0 before any
            bucket has retired. Zero means "no estimate", never "no capacity",
            and every caller has to treat it that way. */
        [[nodiscard]] uint32_t PeakBytesPerBucket() const noexcept
        {
            if (!everComplete) return 0;
            uint32_t peak = 0;
            // From one, because bucket zero is still filling and would report
            // a fraction of its span as though it were the whole of it.
            for (uint32_t i = 1; i < DELIVERY_BUCKETS; ++i)
                if (bucketBytes[i] > peak) peak = bucketBytes[i];
            return peak;
        }

        /** What the path holds: the delivery rate times how long a round trip
            takes. 0 when either input is missing, which reads as "unknown". */
        [[nodiscard]] uint64_t PathBytes(uint32_t minRttMicros) const noexcept
        {
            const uint32_t peak = PeakBytesPerBucket();
            if (peak == 0 || minRttMicros == 0) return 0;
            return static_cast<uint64_t>(peak) * minRttMicros / DELIVERY_BUCKET_MICROS;
        }

        /** Whether `inFlightBytes` is enough to have overflowed anything on a
            path of this capacity.

            True when nothing is known, so a sender that has not measured yet
            keeps the behaviour it had before this existed. Being wrong in that
            direction costs a trim that was already being taken. */
        [[nodiscard]] bool CouldOverflow(uint32_t minRttMicros,
                                         uint64_t inFlightBytes) const noexcept
        {
            const uint64_t path = PathBytes(minRttMicros);
            if (path == 0) return true;
            return inFlightBytes * 100 >= path * CC_OVERFLOW_GATE_PERCENT;
        }
    };
}
