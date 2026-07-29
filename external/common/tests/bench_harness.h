#pragma once

// Minimal benchmark harness. A bench measures ns/op for one of our structures
// and for the standard-library baseline a competent engineer would reach for by
// default, then prints both with the speedup between them.
//
// It is a measurement tool, not a pass/fail gate: absolute timings are
// machine-specific, so the benches always exit 0 and the printed number is the
// signal. Read it two ways — against the baseline ratio (does the hand-built
// structure actually earn its complexity?) and against previous runs on the
// same machine (did a change add unexpected overhead?). Run them on demand:
//   ctest -L bench --output-on-failure
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <vector>

namespace bench
{
    // A sink the optimizer cannot see through, so measured work is never elided.
    inline volatile uint64_t sink = 0;

    // Nanoseconds per call, averaged over `iterations` timed runs after `warmup`
    // untimed ones. body() performs exactly one operation.
    template <typename Body>
    double ns_per_op(uint64_t iterations, uint64_t warmup, Body body)
    {
        for (uint64_t i = 0; i < warmup; ++i) body();

        auto start = std::chrono::steady_clock::now();
        for (uint64_t i = 0; i < iterations; ++i) body();
        auto end = std::chrono::steady_clock::now();

        double nanos = std::chrono::duration<double, std::nano>(end - start).count();
        return nanos / static_cast<double>(iterations);
    }

    // Millions of operations per second for a given ns/op.
    inline double mops(double nsPerOp) { return nsPerOp > 0.0 ? 1000.0 / nsPerOp : 0.0; }

    // One "ours vs the std baseline" line, with the speedup (baseline / ours).
    inline void compare(const char* label, double oursNs, double baselineNs)
    {
        std::printf("  %-26s ours %8.2f ns/op (%7.2f Mops)   std %8.2f ns/op (%7.2f Mops)   %5.2fx\n",
                    label, oursNs, mops(oursNs), baselineNs, mops(baselineNs),
                    oursNs > 0.0 ? baselineNs / oursNs : 0.0);
    }

    // One standalone measurement line, no baseline.
    inline void report(const char* label, double nsPerOp)
    {
        std::printf("  %-26s %8.2f ns/op (%7.2f Mops)\n", label, nsPerOp, mops(nsPerOp));
    }

    // A throughput line: total ops completed across `threads` threads in a
    // measured wall-clock window.
    inline void throughput(const char* label, uint64_t ops, double seconds, int threads)
    {
        double mopsTotal = (seconds > 0.0) ? (static_cast<double>(ops) / seconds) / 1e6 : 0.0;
        std::printf("  %-26s %2d thread(s): %11llu ops in %6.3f s = %8.2f Mops/s\n",
                    label, threads, static_cast<unsigned long long>(ops), seconds, mopsTotal);
    }

    // One operation's latency distribution; sorts the samples in place.
    // Contended designs differ most in the tail — two structures tied on
    // throughput can sit orders of magnitude apart at p99.9 — so contended
    // benches report this alongside the mean.
    inline void latency(const char* label, std::vector<uint32_t>& samplesNs)
    {
        if (samplesNs.empty()) return;
        std::sort(samplesNs.begin(), samplesNs.end());
        auto at = [&](double p)
        {
            return samplesNs[static_cast<size_t>(static_cast<double>(samplesNs.size() - 1) * p)];
        };
        std::printf("  %-26s p50 %7u   p99 %9u   p99.9 %10u   worst %11u   (ns)\n",
                    label, at(0.50), at(0.99), at(0.999), samplesNs.back());
    }
}
