#pragma once

#include <cstddef>
#include <cstdint>

#include <flux/internal/constants.h>

namespace bcp::flux::wire
{
    /** Packing several messages into one packet's content.

        A packet either carries one message filling its content, exactly as it
        always has, or a list of messages each behind a two-byte length. The
        first message is written with no length in front of it, and the length
        is inserted retroactively when a second message arrives. That is what
        keeps a packet carrying one message identical on the wire to an
        unbatched one, so a caller that sends one message per flush pays
        nothing for a feature it is not using.

        Content is the region after the packet's own header. Everything here
        addresses it from its start and knows nothing about what precedes it,
        so the same code serves whatever header the packet turned out to need.

        The limit is passed in rather than read from a constant, because it
        becomes a per-peer discovered MTU later and the packer should not have
        to change when it does. */
    struct BatchCursor
    {
        uint8_t* content;    ///< first byte after the packet header
        uint16_t used;       ///< content bytes written so far
        uint16_t count;      ///< messages written so far
        uint16_t firstLen;   ///< length of the first, which carries no prefix
        uint16_t capacity;   ///< content bytes available, the limit less the header
    };

    /** Content bytes a message of `len` would consume, counting the prefix it
        needs and, when it is the second message, the prefix that has to be
        inserted in front of the first. Returns 0 if `len` cannot be framed. */
    [[nodiscard]] uint32_t BatchCostOf(const BatchCursor& cursor, uint16_t len) noexcept;

    /** Whether the message still fits. */
    [[nodiscard]] bool BatchFits(const BatchCursor& cursor, uint16_t len) noexcept;

    /** Copies the message in and updates the cursor. Shifts the first message
        forward to make room for its length when this is the second one.

        @return false and leaves the cursor untouched when it does not fit, so
                a refused append never half-writes a batch. */
    [[nodiscard]] bool BatchAppend(BatchCursor& cursor, const uint8_t* message,
                                   uint16_t len) noexcept;

    /** Walks the length chain over a received batch's content.

        The lengths must consume the content exactly. A walk that runs past the
        end, or stops short and leaves a tail, means the framing cannot be
        trusted, and a caller that trusted the entries it had already read would
        be trusting bytes chosen by whatever produced the damage.

        @return false when the chain does not land exactly on the end. */
    [[nodiscard]] bool BatchValidate(const uint8_t* content, uint16_t len) noexcept;

    /** Reads the message at `offset`, advancing it past the entry.

        @return false when the entry does not fit the content, which
                BatchValidate has already ruled out for a validated batch. */
    [[nodiscard]] bool BatchNext(const uint8_t* content, uint16_t len, uint16_t& offset,
                                 const uint8_t*& message, uint16_t& messageLen) noexcept;
}
