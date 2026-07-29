#pragma once

#include <cstdio>

// Minimal test harness. A test file runs its cases from main() and ends with
// `return test::report();`, so it reads top to bottom with no framework to
// learn. CHECK records a failure with its location and keeps going, so one run
// reports every failure. The process exits non-zero when any check fails, which
// is the signal CTest keys on.
namespace test
{
    inline int checks   = 0;
    inline int failures = 0;

    inline void fail(const char* file, int line, const char* expr)
    {
        std::printf("  FAIL  %s:%d  %s\n", file, line, expr);
        ++failures;
    }

    inline int report()
    {
        if (failures == 0)
            std::printf("PASS  (%d checks)\n", checks);
        else
            std::printf("FAIL  (%d of %d checks failed)\n", failures, checks);
        return failures == 0 ? 0 : 1;
    }
}

#define CHECK(expr) \
    do { ++test::checks; if (!(expr)) test::fail(__FILE__, __LINE__, #expr); } while (0)
