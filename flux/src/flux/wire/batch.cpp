#include <flux/wire/batch.h>

#include <cstring>

namespace bcp::flux::wire
{
    namespace
    {
        constexpr uint16_t LEN = internal::WIRE_BATCH_LEN_SIZE;

        void PutLen(uint8_t* at, uint16_t value) noexcept
        {
            at[0] = static_cast<uint8_t>(value >> 0);
            at[1] = static_cast<uint8_t>(value >> 8);
        }

        [[nodiscard]] uint16_t TakeLen(const uint8_t* at) noexcept
        {
            return static_cast<uint16_t>(static_cast<uint16_t>(at[0])
                 | static_cast<uint16_t>(static_cast<uint16_t>(at[1]) << 8));
        }
    }

    uint32_t BatchCostOf(const BatchCursor& cursor, uint16_t len) noexcept
    {
        if (len == 0) return 0;   // an empty message has no length that frames it

        // The first message is stored bare, so it costs its own bytes only. The
        // second pays twice: its own prefix, and the prefix the first one has
        // to grow now that it is no longer alone.
        if (cursor.count == 0) return len;
        if (cursor.count == 1) return static_cast<uint32_t>(LEN) + LEN + len;
        return static_cast<uint32_t>(LEN) + len;
    }

    bool BatchFits(const BatchCursor& cursor, uint16_t len) noexcept
    {
        const uint32_t cost = BatchCostOf(cursor, len);
        if (cost == 0) return false;
        return static_cast<uint32_t>(cursor.used) + cost <= cursor.capacity;
    }

    bool BatchAppend(BatchCursor& cursor, const uint8_t* message, uint16_t len) noexcept
    {
        if (!message || !cursor.content) return false;
        if (!BatchFits(cursor, len)) return false;

        if (cursor.count == 0)
        {
            std::memcpy(cursor.content, message, len);
            cursor.used     = len;
            cursor.firstLen = len;
            cursor.count    = 1;
            return true;
        }

        if (cursor.count == 1)
        {
            // The first message was written bare. Shift it up to open the two
            // bytes its length needs, then it is an ordinary entry like the
            // rest and this one appends behind it.
            //
            // memmove, not memcpy: source and destination overlap by every byte
            // but the two it moves. memcpy is undefined here and happens to
            // produce the right answer on some toolchains, which is the worst
            // kind of wrong because it survives its own test.
            std::memmove(cursor.content + LEN, cursor.content, cursor.firstLen);
            PutLen(cursor.content, cursor.firstLen);
            cursor.used = static_cast<uint16_t>(cursor.used + LEN);
        }

        PutLen(cursor.content + cursor.used, len);
        std::memcpy(cursor.content + cursor.used + LEN, message, len);
        cursor.used  = static_cast<uint16_t>(cursor.used + LEN + len);
        cursor.count = static_cast<uint16_t>(cursor.count + 1);
        return true;
    }

    bool BatchValidate(const uint8_t* content, uint16_t len) noexcept
    {
        if (!content) return false;

        uint32_t offset = 0;
        while (offset + LEN <= len)
        {
            const uint16_t entry = TakeLen(content + offset);
            if (entry == 0) return false;                  // an entry frames nothing
            offset += static_cast<uint32_t>(LEN) + entry;
            if (offset > len) return false;                // the entry runs past the end
        }
        // What is left is a tail too short to even be a length, so the chain
        // failed to account for every byte and the framing is not trustworthy.
        return offset == len;
    }

    bool BatchNext(const uint8_t* content, uint16_t len, uint16_t& offset,
                   const uint8_t*& message, uint16_t& messageLen) noexcept
    {
        if (!content || offset >= len) return false;
        if (static_cast<uint32_t>(offset) + LEN > len) return false;

        const uint16_t entry = TakeLen(content + offset);
        if (static_cast<uint32_t>(offset) + LEN + entry > len) return false;

        message    = content + offset + LEN;
        messageLen = entry;
        offset     = static_cast<uint16_t>(offset + LEN + entry);
        return true;
    }
}
