// ReplayWindow integrity. A genuine counter is accepted once; a duplicate, a
// counter older than the window, and the reserved 0 are all rejected; reorder
// within the window is tolerated (UDP delivers out of order); and Reset reopens
// the window for a re-key. The caller owns state[0] = high-water mark and
// state[1..words] = the seen bitmap; one word covers 64 counters.
#include <flux/internal/replay_window.h>

#include "harness.h"

#include <cstdint>

using bcp::flux::ReplayWindow;

// A fresh counter is accepted once; a repeat of it is rejected.
static void accepts_new_rejects_duplicate()
{
    uint64_t state[2] = {0, 0};
    ReplayWindow window{state, 1};
    window.Reset();

    CHECK(window.Accept(1));    // first genuine packet
    CHECK(!window.Accept(1));   // exact replay
    CHECK(window.Accept(2));
    CHECK(!window.Accept(2));
}

// Counter 0 is reserved for "nothing seen yet" and is always rejected.
static void rejects_zero()
{
    uint64_t state[2] = {0, 0};
    ReplayWindow window{state, 1};
    window.Reset();

    CHECK(!window.Accept(0));
}

// A counter that arrives after a higher one but still inside the window is new
// and accepted; replaying it afterwards is rejected.
static void tolerates_reorder_within_window()
{
    uint64_t state[2] = {0, 0};
    ReplayWindow window{state, 1};
    window.Reset();

    CHECK(window.Accept(5));    // jump ahead
    CHECK(window.Accept(3));    // older, but never seen and within the window
    CHECK(window.Accept(4));
    CHECK(!window.Accept(3));   // now a duplicate
}

// A counter older than the window (one word = 64 counters back from the
// high-water mark) is rejected as too old.
static void rejects_older_than_window()
{
    uint64_t state[2] = {0, 0};
    ReplayWindow window{state, 1};
    window.Reset();

    CHECK(window.Accept(100));   // high-water mark is now 100
    CHECK(window.Accept(37));    // 100 - 63: still the oldest the window covers
    CHECK(!window.Accept(36));   // 100 - 64: fallen off the back
}

// Reset clears the mark and bitmap, so a counter seen before the reset is
// accepted again — the state both sides need after re-keying to counter 1.
static void reset_reopens_window()
{
    uint64_t state[2] = {0, 0};
    ReplayWindow window{state, 1};
    window.Reset();

    CHECK(window.Accept(1));
    CHECK(!window.Accept(1));
    window.Reset();
    CHECK(window.Accept(1));     // fresh again after re-key
}

int main()
{
    accepts_new_rejects_duplicate();
    rejects_zero();
    tolerates_reorder_within_window();
    rejects_older_than_window();
    reset_reopens_window();
    return test::report();
}
