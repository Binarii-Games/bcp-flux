// NextPowerOfTwo correctness. It sizes every ring buffer in the collections
// (FifoQueue, SlotPool, the peer-table indexes), so the rounding has to be
// exact: the smallest power of two not smaller than n, and at least 1.
#include <common/math.h>

#include "harness.h"

#include <cstdint>

using bcp::common::NextPowerOfTwo;

// Rounds up to the next power of two; an exact power of two is left alone.
static void rounds_up_to_power_of_two()
{
    CHECK(NextPowerOfTwo(0) == 1);   // a zero request still yields a usable ring
    CHECK(NextPowerOfTwo(1) == 1);
    CHECK(NextPowerOfTwo(2) == 2);
    CHECK(NextPowerOfTwo(3) == 4);
    CHECK(NextPowerOfTwo(4) == 4);
    CHECK(NextPowerOfTwo(5) == 8);
    CHECK(NextPowerOfTwo(7) == 8);
    CHECK(NextPowerOfTwo(8) == 8);
    CHECK(NextPowerOfTwo(9) == 16);
    CHECK(NextPowerOfTwo(1000) == 1024);
    CHECK(NextPowerOfTwo(1024) == 1024);
    CHECK(NextPowerOfTwo(1u << 30) == (1u << 30));
    CHECK(NextPowerOfTwo((1u << 30) + 1) == (1u << 31));
}

int main()
{
    rounds_up_to_power_of_two();
    return test::report();
}
