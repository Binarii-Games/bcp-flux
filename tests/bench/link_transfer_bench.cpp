// What the protocol does on a link rather than what a packet costs, printed
// as a table. The link itself is in link_model.h, shared with the performance
// gate so the two cannot drift into measuring different things.
//
// One transfer crosses the link once per row: clean, under independent loss at
// one, two and five percent, and under Gilbert-Elliott loss at the same
// averages in bursts of twenty. Independent loss is what thermal noise looks
// like. Real links also lose in bursts, and a burst defeats recovery that
// independent loss of the same average never troubles.
//
// Timings are wall clock through a real scheduler. The burst rows in
// particular move several seconds between runs, because where a burst lands
// against the window decides how much serialises behind the repair, so read
// them as a shape rather than a number. The gate deliberately does not use
// them for that reason.
//
//   link_transfer_bench [MiB] [filter]
//
// MiB defaults to 100. A filter runs only the rows whose label contains it, so
// `link_transfer_bench 1024 clean` is one gigabyte on a clean link.
#include "link_model.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>


int main(int argc, char** argv)
{
    const uint64_t mib = argc > 1 ? static_cast<uint64_t>(std::atoll(argv[1])) : 100;
    const char* filter = argc > 2 ? argv[2] : nullptr;
    const uint64_t payloadBytes = mib * 1024 * 1024;
    const double floorSeconds =
        static_cast<double>(payloadBytes) * 8.0 / (LINK_KBIT * 1000.0);

    // Burst rows lose everything while the chain sits in the bad state, so the
    // average is enter over enter plus exit and the mean burst is 1e6/exit.
    const LossModel scenarios[] = {
        { "clean",            0,     0,    0,     0   },
        { "1% independent",   10000, 0,    0,     0   },
        { "2% independent",   20000, 0,    0,     0   },
        { "5% independent",   50000, 0,    0,     0   },
        { "1% bursts of 20",  0,     505,  50000, 100 },
        { "2% bursts of 20",  0,     1020, 50000, 100 },
        { "5% bursts of 20",  0,     2632, 50000, 100 },
    };

    std::printf("link: 50 Mbit, 40 ms round trip, 250 KB tail-drop queue, relay in process\n");
    std::printf("payload: %llu MiB as one transfer, floor at the link rate %.1f s\n\n",
                (unsigned long long)mib, floorSeconds);

    const char* rule = "  +-------------------+-----------+-------------+---------------+\n";
    std::printf("%s", rule);
    std::printf("  | loss              |      time |        rate |   of the link |\n");
    std::printf("%s", rule);
    std::fflush(stdout);

    uint16_t basePort = 9700;
    for (const LossModel& scenario : scenarios)
    {
        if (filter && !std::strstr(scenario.label, filter)) continue;
        const double seconds = RunScenario(scenario, payloadBytes, basePort);
        basePort = static_cast<uint16_t>(basePort + 10);
        if (seconds > 0.0)
        {
            const double mbit = static_cast<double>(payloadBytes) * 8.0 / (seconds * 1e6);
            std::printf("  | %-17s | %6.2f s  | %5.1f Mbit  | %10.0f %%  |\n",
                        scenario.label, seconds, mbit,
                        mbit * 100.0 / (LINK_KBIT / 1000.0));
        }
        else
            std::printf("  | %-17s |    DNF    |      -      | over 5x floor |\n",
                        scenario.label);
        std::fflush(stdout);
    }
    std::printf("%s", rule);
    return 0;
}
