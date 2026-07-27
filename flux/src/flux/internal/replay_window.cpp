#include <flux/internal/replay_window.h>

namespace bcp::flux
{
    void ReplayWindow::Reset() noexcept
    {
        for (uint32_t i = 0; i < 1 + words; ++i)
            state[i] = 0;
    }

    bool ReplayWindow::Accept(uint64_t counter) noexcept
    {
        if (counter == 0)
            return false;   // 0 is the sentinel; real counters are >= 1

        uint64_t&      high = state[0];
        uint64_t*      bmp  = state + 1;
        const uint64_t bits = static_cast<uint64_t>(words) * 64;

        if (counter > high)
        {
            // New highest: slide the window by the gap. Bit i holds counter
            // (high - i), so advancing by diff shifts every bit up by diff;
            // a jump past the window empties it.
            const uint64_t diff = counter - high;
            if (diff >= bits)
            {
                for (uint32_t i = 0; i < words; ++i)
                    bmp[i] = 0;
            }
            else
            {
                const uint32_t wordShift = static_cast<uint32_t>(diff / 64);
                const uint32_t bitShift  = static_cast<uint32_t>(diff % 64);
                for (int w = static_cast<int>(words) - 1; w >= 0; --w)
                {
                    const int src = w - static_cast<int>(wordShift);
                    uint64_t v = 0;
                    if (src >= 0)
                    {
                        v = bmp[src] << bitShift;
                        if (bitShift != 0 && src - 1 >= 0)
                            v |= bmp[src - 1] >> (64 - bitShift);
                    }
                    bmp[w] = v;
                }
            }
            bmp[0] |= 1u;   // mark the new high (bit 0) as seen
            high = counter;
            return true;
        }

        // At or below the high-water mark.
        const uint64_t diff = high - counter;
        if (diff >= bits)
            return false;   // older than the window; can't prove it isn't a replay

        const uint32_t word = static_cast<uint32_t>(diff / 64);
        const uint64_t mask = uint64_t{1} << (diff % 64);
        if (bmp[word] & mask)
            return false;   // already seen; replay
        bmp[word] |= mask;
        return true;
    }
}
