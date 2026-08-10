// The performance the transport is expected to keep, as a test rather than a
// printed number.
//
// A benchmark says what happened. This says what must not stop being true, so
// a change that quietly costs a third of the throughput fails here instead of
// being noticed months later. It moves one transfer across the same in-process
// bottleneck the bench uses, at 50 Mbit with a 40 ms round trip and a queue of
// one bandwidth-delay product.
//
// TWO THINGS MAKE THIS SAFE TO RUN ON A MACHINE NOBODY CHOSE.
//
// The link is the bottleneck, not the processor. Fifty megabits is about 5400
// packets a second, which any machine that can run the suite can serve, so the
// time to move a payload is set by the emulated link rather than by how fast
// the host is. That is what makes an absolute threshold meaningful here when
// it would be worthless on a nanoseconds-per-operation bench.
//
// And the loss rows are judged against the clean row from the same run rather
// than against a constant. The clean row absorbs whatever the host is worth on
// the day, so what remains is the property actually under test: how much of
// the link survives loss. A slow runner moves both numbers together and the
// ratio holds.
//
// ONLY THE STABLE ROWS ARE HERE. The burst-loss rows in the bench swing by up
// to forty percent between runs on one machine, because a seeded model fixes
// which packets drop but not where a burst falls against the window, and that
// placement is what decides how much serialises behind the repair. Gating on
// them would produce a test that fails for no reason, which is worse than no
// test. They stay in the bench, where a human reads them as a shape.
//
// Build Release. A sanitized build runs the same link at about 78 percent
// where Release holds 90, so it measures the sanitizer rather than the
// transport, and the thresholds below would be wrong for it.
#include "link_model.h"

#include "harness.h"

#include <cstdio>

namespace
{
    /* 100 MiB, because smaller does not work. At 25 MiB the ramp is a large
       enough fraction of the run that the one percent row came in slower than
       the five percent row, which is noise wearing the shape of a
       measurement. */
    constexpr uint64_t PAYLOAD_BYTES = 100ull * 1024 * 1024;

    /* Seconds a perfect sender would need at the link rate. Everything below
       is expressed against this or against the clean row. */
    double FloorSeconds()
    {
        return static_cast<double>(PAYLOAD_BYTES) * 8.0 / (LINK_KBIT * 1000.0);
    }

    /* The clean row doubles as the machine check. Measured at 1.04 times the
       floor on the reference machine and identical across three runs, so the
       margin here is for a slower host rather than for variance in the
       transport. Past this, either the host cannot serve the link or something
       has gone badly wrong, and the ratios below would not be meaningful
       either way. */
    constexpr double CLEAN_MAX_OVER_FLOOR = 1.35;

    struct Row
    {
        const char* name;
        LossModel   loss;
        double      maxOverClean;   ///< ceiling as a multiple of this run's clean time
        double      reference;      ///< what the reference machine measured, for the report
    };

    /* Ceilings sit roughly twice the observed distance above the clean row, so
       ordinary variance passes and a real loss of throughput does not. Three
       runs on the reference machine gave 1.07, 1.08 and 1.15 times clean for
       the three rows below. */
    const Row ROWS[] = {
        { "1% independent", { "1% independent", 10000, 0, 0, 0 }, 1.20, 1.07 },
        { "2% independent", { "2% independent", 20000, 0, 0, 0 }, 1.25, 1.08 },
        { "5% independent", { "5% independent", 50000, 0, 0, 0 }, 1.35, 1.15 },
    };
}

int main()
{
    const double floorSeconds = FloorSeconds();
    std::printf("link 50 Mbit / 40 ms / 1 BDP, payload %llu MiB, floor %.1f s\n\n",
                (unsigned long long)(PAYLOAD_BYTES / (1024 * 1024)), floorSeconds);

    /* The control, first, because every ratio below is taken against it. */
    const LossModel clean{ "clean", 0, 0, 0, 0 };
    const double cleanSeconds = RunScenario(clean, PAYLOAD_BYTES, 9880);

    if (cleanSeconds <= 0.0)
    {
        std::printf("  clean run did not finish, nothing below can be judged\n");
        CHECK(cleanSeconds > 0.0);
        return test::report();
    }

    const double cleanOverFloor = cleanSeconds / floorSeconds;
    std::printf("  %-16s %7.2f s   %.2fx floor   ceiling %.2fx\n",
                "clean", cleanSeconds, cleanOverFloor, CLEAN_MAX_OVER_FLOOR);
    CHECK(cleanOverFloor <= CLEAN_MAX_OVER_FLOOR);

    uint16_t port = 9890;
    for (const Row& row : ROWS)
    {
        const double seconds = RunScenario(row.loss, PAYLOAD_BYTES, port);
        port = static_cast<uint16_t>(port + 10);

        if (seconds <= 0.0)
        {
            std::printf("  %-16s did not finish\n", row.name);
            CHECK(seconds > 0.0);
            continue;
        }

        const double overClean = seconds / cleanSeconds;
        std::printf("  %-16s %7.2f s   %.2fx clean    ceiling %.2fx   (reference %.2fx)\n",
                    row.name, seconds, overClean, row.maxOverClean, row.reference);
        CHECK(overClean <= row.maxOverClean);
    }

    return test::report();
}
