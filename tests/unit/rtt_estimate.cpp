// The path timing a peer keeps: the smoothed round trip, the remembered
// minimum, the queue those two imply, and the two deadlines built from them.
//
// Every expected value here is arithmetic on the documented formula rather
// than a figure read back from a run, so a change in behaviour fails rather
// than being adopted. No clock and no socket are involved: the struct takes
// the time as an argument, which is what makes these exact.
#include <flux/internal/rtt.h>

#include "harness.h"

#include <cstdint>

using bcp::flux::internal::RttEstimate;
namespace internal = bcp::flux::internal;

namespace
{
    RttEstimate Fresh()
    {
        RttEstimate rtt{};
        rtt.Reset();
        return rtt;
    }
}

// The first sample is the average, with half of it as the deviation. Later
// ones fold by Jacobson/Karels, and the deviation folds FIRST so it measures
// the gap against the average this sample is judged by rather than the one it
// has already moved. Folding in the other order gives 875 here, not 625.
static void folds_by_jacobson_karels()
{
    RttEstimate rtt = Fresh();

    CHECK(rtt.Sample(1000, 0, 0));
    CHECK(rtt.srttMicros   == 1000);
    CHECK(rtt.rttvarMicros == 500);

    // diff 1000, so rttvar = (500*3 + 1000)/4 and srtt = (1000*7 + 2000)/8.
    CHECK(rtt.Sample(2000, 0, 0));
    CHECK(rtt.rttvarMicros == 625);
    CHECK(rtt.srttMicros   == 1125);

    // A sample equal to the average moves the average nowhere and decays the
    // deviation by a quarter.
    CHECK(rtt.Sample(1125, 0, 0));
    CHECK(rtt.srttMicros   == 1125);
    CHECK(rtt.rttvarMicros == 468);
}

// A round trip of zero or one past the ceiling did not come from the network,
// it came from subtracting something that was never a timestamp. One of those
// folded in poisons every decision built on the average afterwards, so it is
// refused and nothing changes.
static void refuses_a_sample_that_is_not_a_measurement()
{
    RttEstimate rtt = Fresh();
    CHECK(rtt.Sample(1000, 0, 0));

    CHECK(!rtt.Sample(0, 0, 0));
    CHECK(rtt.srttMicros   == 1000);
    CHECK(rtt.latestMicros == 1000);

    CHECK(!rtt.Sample(internal::RTT_SAMPLE_MAX_MICROS + 1, 0, 0));
    CHECK(rtt.srttMicros   == 1000);
    CHECK(rtt.latestMicros == 1000);

    // The ceiling itself is a measurement, so it is taken.
    CHECK(rtt.Sample(internal::RTT_SAMPLE_MAX_MICROS, 0, 0));
    CHECK(rtt.latestMicros == internal::RTT_SAMPLE_MAX_MICROS);
}

// Inside one bucket the remembered minimum can only fall, which is what makes
// it the empty-road time. Across a full set of rotations it can rise again,
// which is what stops a route change from leaving the sender measuring queue
// against a path that no longer exists.
static void the_minimum_falls_within_a_bucket_and_rises_across_them()
{
    RttEstimate rtt = Fresh();
    const uint64_t start = 1000000;

    CHECK(rtt.Sample(5000, 0, start));
    CHECK(rtt.MinRttMicros() == 5000);

    CHECK(rtt.Sample(20000, 0, start));
    CHECK(rtt.MinRttMicros() == 5000);   // a higher sample cannot raise it here

    // Every bucket retires, so nothing older than the window survives.
    const uint64_t later = start
        + internal::MIN_RTT_BUCKETS * internal::MIN_RTT_BUCKET_MICROS;
    CHECK(rtt.Sample(20000, 0, later));
    CHECK(rtt.MinRttMicros() == 20000);
}

// The two queue readings are the same subtraction against different numerator
// s, and the gap between them is the point. The newest sample crosses a
// threshold the moment a queue forms while the average is still catching up,
// which is why the ramp watches the newest and the governor watches the
// average.
static void the_newest_sample_sees_the_queue_before_the_average()
{
    RttEstimate rtt = Fresh();

    CHECK(rtt.Sample(10000, 0, 0));
    CHECK(rtt.QueueMicros()       == 0);
    CHECK(rtt.LatestQueueMicros() == 0);

    // srtt becomes 15000 against a minimum still at 10000, latest is 50000.
    CHECK(rtt.Sample(50000, 0, 0));
    CHECK(rtt.MinRttMicros()      == 10000);
    CHECK(rtt.QueueMicros()       == 5000);
    CHECK(rtt.LatestQueueMicros() == 40000);
}

// On a steady path the deviation decays toward its flat floor, which is
// microscopic against a long round trip, and a deadline that close to the
// average duplicates whatever honestly runs a few percent late. The margin
// therefore also scales with the path.
static void the_deadline_keeps_a_margin_proportional_to_the_path()
{
    RttEstimate rtt = Fresh();
    for (uint32_t i = 0; i < 64; ++i) CHECK(rtt.Sample(40000, 0, 0));

    CHECK(rtt.srttMicros == 40000);
    CHECK(rtt.rttvarMicros < 100);   // the variance term has collapsed

    // 40000 of path, an eighth of it as margin, no hold asked for.
    CHECK(rtt.RetransmitTimeout(200000, 0, 0) == 45000);

    // With only the flat floor this would be 41000, and the three percent of
    // packets landing in the spread above the average were all duplicated.
    CHECK(rtt.RetransmitTimeout(200000, 0, 0) > 41000);
}

// The far side's hold is covered by whichever is larger, what it reported and
// the cadence this side runs its own acknowledgements at. The reported figure
// describes the newest sequence in a batch, which is the one that waited
// least, so alone it reads near zero while the older sequences in the same
// batch waited far longer.
static void the_hold_term_takes_the_larger_of_cadence_and_report()
{
    RttEstimate rtt = Fresh();
    CHECK(rtt.Sample(40000, 0, 0));            // rttvar 20000, variance 80000

    // Nothing reported, so the cadence is the floor.
    CHECK(rtt.RetransmitTimeout(200000, 10000, 0) == 40000 + 80000 + 10000);

    // A larger reported hold wins. The same sample decays rttvar to 15000.
    CHECK(rtt.Sample(40000, 50000, 0));
    CHECK(rtt.peerAckDelayMicros == 50000);
    CHECK(rtt.RetransmitTimeout(200000, 10000, 0) == 40000 + 60000 + 50000);
}

// Silence doubles the deadline so a peer that has gone quiet is not asked
// again at the same interval forever, and the doubling is capped so a bad
// moment cannot push the next attempt beyond reach. One acknowledgement
// unwinds all of it.
static void silence_doubles_the_deadline_and_the_doubling_is_capped()
{
    RttEstimate rtt = Fresh();
    const uint64_t start = 1000000;
    CHECK(rtt.Sample(40000, 0, start));
    rtt.MarkAcked(start);

    const uint64_t base = rtt.RetransmitTimeout(200000, 0, start);
    CHECK(base == 120000);                       // 40000 path plus 80000 variance

    // Far more silence than the cap allows for, so the cap is what shows.
    const uint64_t longSilence = start + 100 * base;
    CHECK(rtt.RetransmitTimeout(200000, 0, longSilence) == base * 8);

    rtt.MarkAcked(longSilence);
    CHECK(rtt.RetransmitTimeout(200000, 0, longSilence) == base);
}

// Asked on the very first acknowledgement, before that reply's own sample has
// been folded, so with nothing measured it has to fall back to the caller's
// figure. Reading the raw zero fields instead makes the rule "outstanding
// longer than a millisecond", which declares every packet below the newest
// one lost before a single round trip has been measured.
static void the_loss_delay_falls_back_before_anything_is_measured()
{
    RttEstimate rtt = Fresh();
    CHECK(rtt.LossDelayMicros(200000) == 225000);   // the fallback plus an eighth

    CHECK(rtt.Sample(40000, 0, 0));
    CHECK(rtt.LossDelayMicros(200000) == 45000);    // the measurement plus an eighth
}

// A peer that has never acknowledged anything is not silent, it is new. The
// difference matters because silence is what drives the doubling, and a fresh
// peer reading as silent forever would start at the maximum backoff.
static void a_peer_that_never_answered_is_not_silent()
{
    RttEstimate rtt = Fresh();
    CHECK(rtt.SilentForMicros(1000000) == 0);

    rtt.MarkAcked(2000000);
    CHECK(rtt.SilentForMicros(1000000) == 0);   // a clock behind the stamp
    CHECK(rtt.SilentForMicros(2000000) == 0);
    CHECK(rtt.SilentForMicros(2500000) == 500000);
}

int main()
{
    folds_by_jacobson_karels();
    refuses_a_sample_that_is_not_a_measurement();
    the_minimum_falls_within_a_bucket_and_rises_across_them();
    the_newest_sample_sees_the_queue_before_the_average();
    the_deadline_keeps_a_margin_proportional_to_the_path();
    the_hold_term_takes_the_larger_of_cadence_and_report();
    silence_doubles_the_deadline_and_the_doubling_is_capped();
    the_loss_delay_falls_back_before_anything_is_measured();
    a_peer_that_never_answered_is_not_silent();
    return test::report();
}
