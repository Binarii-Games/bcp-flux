#include <flux/socket/ready_lanes.h>

namespace bcp::flux
{
    bool ReadyLanes::Init(uint32_t laneCount, uint32_t perLaneCapacity) noexcept
    {
        if (perLaneCapacity == 0) return false;

        uint32_t count = 1;
        uint32_t bits  = 0;
        while (count < laneCount && count < MAX_LANES)
        {
            count <<= 1;
            ++bits;
        }

        for (uint32_t i = 0; i < count; ++i)
            if (!lanes_[i].Init(perLaneCapacity))
            {
                Shutdown();
                return false;
            }

        laneCount_ = count;
        laneShift_ = 32 - bits;
        return true;
    }

    uint32_t ReadyLanes::Claim(uint32_t wanted) noexcept
    {
        if (laneCount_ == 0) return NO_LANE;

        // The caller's own lane first, then the rest in order. Trying its own
        // lane first is what makes a thread stay on one lane while nothing is
        // contending, so its peers' state stays in that core's cache.
        const uint32_t start = wanted < laneCount_ ? wanted : 0;
        for (uint32_t i = 0; i < laneCount_; ++i)
        {
            const uint32_t lane = (start + i) % laneCount_;
            if (!busy_[lane].flag.test_and_set(std::memory_order_acquire))
                return lane;
        }
        return NO_LANE;
    }

    void ReadyLanes::Shutdown() noexcept
    {
        for (uint32_t i = 0; i < MAX_LANES; ++i)
            lanes_[i].Shutdown();
        for (uint32_t i = 0; i < MAX_LANES; ++i)
            busy_[i].flag.clear(std::memory_order_relaxed);
        laneCount_ = 0;
        laneShift_ = 32;
    }
}
