// The three pure functions congestion growth is built from: the queue a path
// tolerates, CUBIC's window as a function of time, and the straight line taken
// underneath it.
//
// Exact figures where the arithmetic is exact, and shape where it depends on a
// cube root's rounding. The shape assertions are not the weaker kind: the
// defect this file exists to catch was a curve that had the right endpoints
// and no slope between them.
#include <flux/internal/congestion_curve.h>

#include "harness.h"

#include <cstdint>

namespace internal = bcp::flux::internal;

namespace
{
    // A path holding 250 KB, which is the shaped fifty megabit link at forty
    // milliseconds the head to head runs on.
    constexpr uint32_t W_MAX = 250000;
}

// A fraction of the path's own delay, with a floor. Without the floor an
// eighth of a loopback round trip is single-digit microseconds, ordinary
// scheduling jitter reads as a standing queue, and the window never grows
// again from the opening one.
static void the_queue_target_is_a_fraction_with_a_floor()
{
    CHECK(internal::QueueTargetMicros(40000) == 5000);
    CHECK(internal::QueueTargetMicros(80000) == 10000);

    // An eighth of these lands under the floor, so the floor is what applies.
    CHECK(internal::QueueTargetMicros(4000) == internal::QUEUE_TARGET_MIN_MICROS);
    CHECK(internal::QueueTargetMicros(50)   == internal::QUEUE_TARGET_MIN_MICROS);
    CHECK(internal::QueueTargetMicros(0)    == internal::QUEUE_TARGET_MIN_MICROS);
}

// The curve starts where the trim left the window and climbs back toward the
// window that was running when trouble appeared. At the moment of the
// reduction it sits at roughly the retained fraction, which is what makes the
// trim and the curve one continuous motion rather than two.
static void the_curve_starts_at_the_trim_and_returns_to_the_previous_window()
{
    const uint64_t atReduction = internal::CubicWindow(W_MAX, 0);
    const uint64_t retained    = W_MAX * internal::CC_LOSS_RETAIN_PERCENT / 100;

    CHECK(atReduction < W_MAX);
    CHECK(atReduction > retained - retained / 20);   // within five percent
    CHECK(atReduction < retained + retained / 20);

    // Far enough past the inflection and it is above the old window, which is
    // the probing half of the shape.
    CHECK(internal::CubicWindow(W_MAX, 20000000) > W_MAX);
}

// THE DEFECT THIS FILE EXISTS FOR. Cubing three separately truncated second
// counts gives C * floor(t)^3, which is flat in whole-second steps: two points
// inside one second return the same window, and with the inflection several
// seconds out the entire concave phase collapsed to a couple of values. The
// controller was then Reno wearing CUBIC's name.
static void the_curve_moves_within_a_single_second()
{
    // Every tenth of a second must move the window somewhere the curve is
    // steep. Comparing two points a half second apart is not enough: they can
    // straddle a whole-second boundary and clear the truncated version too,
    // which this test did until the bug was reintroduced to check it.
    uint64_t previous = internal::CubicWindow(W_MAX, 10000000);
    for (uint64_t elapsed = 10100000; elapsed <= 15000000; elapsed += 100000)
    {
        const uint64_t window = internal::CubicWindow(W_MAX, elapsed);
        CHECK(window > previous);
        previous = window;
    }
}

// Time only moves the window one way between reductions.
static void the_curve_never_goes_backwards()
{
    uint64_t previous = 0;
    for (uint64_t elapsed = 0; elapsed <= 20000000; elapsed += 250000)
    {
        const uint64_t window = internal::CubicWindow(W_MAX, elapsed);
        CHECK(window >= previous);
        previous = window;
    }
}

// A peer with no remembered window has no curve to follow.
static void the_curve_is_zero_without_an_anchor()
{
    CHECK(internal::CubicWindow(0, 0) == 0);
    CHECK(internal::CubicWindow(0, 10000000) == 0);
}

// The straight line: the retained window plus a fixed step per round trip
// elapsed. Every figure here is exact, so the constants cannot drift without
// this failing.
static void the_straight_line_adds_a_fixed_step_per_round()
{
    // 1200 * 3 * 30 / 170, the standard Reno-friendly increase.
    constexpr uint64_t PER_ROUND = 1200ull * 3 * 30 / 170;
    constexpr uint64_t RETAINED  = W_MAX * 70 / 100;

    CHECK(internal::RenoWindow(W_MAX, 0,      40000) == RETAINED);
    CHECK(internal::RenoWindow(W_MAX, 40000,  40000) == RETAINED + PER_ROUND);
    CHECK(internal::RenoWindow(W_MAX, 400000, 40000) == RETAINED + 10 * PER_ROUND);

    // A partial round has not completed, so it adds nothing.
    CHECK(internal::RenoWindow(W_MAX, 39999, 40000) == RETAINED);
}

// Nothing has been timed, so there are no round trips to count.
static void the_straight_line_is_zero_without_a_round_trip()
{
    CHECK(internal::RenoWindow(W_MAX, 1000000, 0) == 0);
}

// Why the straight line is kept underneath the curve at all. CUBIC is sized
// for windows that take many round trips to rebuild, so on a short path it
// climbs slower than Reno would, and a short path should never be punished
// for running a controller designed for long ones.
static void the_straight_line_wins_on_a_short_path()
{
    constexpr uint64_t ONE_SECOND = 1000000;
    constexpr uint32_t SHORT_RTT  = 5000;

    CHECK(internal::RenoWindow(W_MAX, ONE_SECOND, SHORT_RTT)
        > internal::CubicWindow(W_MAX, ONE_SECOND));

    // And why the curve is kept: on a long path the line barely moves, while
    // the curve recovers in the same wall-clock time whatever the distance.
    constexpr uint32_t LONG_RTT = 200000;
    CHECK(internal::RenoWindow(W_MAX, 20000000, LONG_RTT)
        < internal::CubicWindow(W_MAX, 20000000));
}

int main()
{
    the_queue_target_is_a_fraction_with_a_floor();
    the_curve_starts_at_the_trim_and_returns_to_the_previous_window();
    the_curve_moves_within_a_single_second();
    the_curve_never_goes_backwards();
    the_curve_is_zero_without_an_anchor();
    the_straight_line_adds_a_fixed_step_per_round();
    the_straight_line_is_zero_without_a_round_trip();
    the_straight_line_wins_on_a_short_path();
    return test::report();
}
