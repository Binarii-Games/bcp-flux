#pragma once

#include <cstdint>

#include <common/math.h>
#include <flux/internal/constants.h>

/** The three pure functions the congestion controller's growth is built from.

    They take numbers and return numbers, touching no peer and no socket, which
    is what lets the curve be checked against its formula directly. The policy
    that decides when to consult them lives with the peer, in
    `peer/congestion.cpp`. */
namespace bcp::flux::internal
{
    /** How much standing queue this path tolerates before growth stops.

        A fraction of the path's own delay, floored, because a fraction of a
        very short path lands below the noise: on loopback an eighth of the
        minimum is single-digit microseconds and ordinary scheduling jitter
        is larger than that, so the sender reads a queue that is not there
        and never grows again. */
    [[nodiscard]] inline uint32_t QueueTargetMicros(uint32_t minRttMicros) noexcept
    {
        const uint32_t target = minRttMicros / QUEUE_TARGET_DIVISOR;
        return target < QUEUE_TARGET_MIN_MICROS ? QUEUE_TARGET_MIN_MICROS : target;
    }

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
    [[nodiscard]] inline uint64_t CubicWindow(uint32_t wMaxBytes,
                                              uint64_t elapsedMicros) noexcept
    {
        // C in bytes per second cubed, from the standard 0.4 in packets.
        const uint64_t cBytes = static_cast<uint64_t>(CC_CUBIC_C_SCALED)
                              * MAX_WIRE_PACKET_SIZE / CC_CUBIC_C_SCALE;
        if (cBytes == 0 || wMaxBytes == 0) return wMaxBytes;

        const uint64_t reduction = static_cast<uint64_t>(wMaxBytes)
                                 * (100 - CC_LOSS_RETAIN_PERCENT) / 100;

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
    [[nodiscard]] inline uint64_t RenoWindow(uint32_t wMaxBytes, uint64_t elapsedMicros,
                                             uint32_t srttMicros) noexcept
    {
        if (srttMicros == 0) return 0;
        const uint64_t retained = static_cast<uint64_t>(wMaxBytes)
                                * CC_LOSS_RETAIN_PERCENT / 100;
        const uint64_t rounds   = elapsedMicros / srttMicros;
        const uint64_t perRound = static_cast<uint64_t>(MAX_WIRE_PACKET_SIZE)
                                * 3 * (100 - CC_LOSS_RETAIN_PERCENT)
                                / (100 + CC_LOSS_RETAIN_PERCENT);
        return retained + rounds * perRound;
    }
}
