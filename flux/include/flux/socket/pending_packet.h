#pragma once

#include <cstdint>

#include <common/error.h>
#include <common/collections/slot_pool.h>

#include <flux/address.h>
#include <flux/peer/peer_handle.h>
#include <flux/socket/packet_slot.h>

namespace bcp::flux
{
    /** One outgoing packet parked while its peer's handshake completes. Lives in
        the socket's pending SlotPool; `next` is the slot index of the peer's
        following pending packet (SlotPool::INVALID at the tail), letting a peer
        hold an unbounded queue while storing only head and tail.

        `active` is a tripwire for stale slot indices: 1 while the packet is
        linked in a peer's list, 0 once it is detached. A reader holding an index
        whose slot shows 0 is looking at a packet already sent or cleared (or a
        recycled slot). Detach-time clearing keeps the invariant self-maintaining:
        a slot back in the pool is always inactive, so a new occupant can never
        inherit a stale 1. */
    struct PendingPacket
    {
        uint32_t next;
        uint8_t  active;
        uint8_t  requireAuth;   ///< parked by SendSecured: dropped at flush time
                                ///< unless the peer came out authenticated
        uint8_t  retained;      ///< a reliable flow's body: the flush must put it
                                ///< back in a STAGING slot, because the in-flight
                                ///< ring keeps that slot as the retransmit source
                                ///< and releases it there. A kernel slot handed
                                ///< to the ring would be freed into the wrong
                                ///< pool when the packet resolves.
        Address  address;
        uint16_t dataSize;
        uint8_t  data[];
    };

    /** FIFO over a peer's pending list. Exclusivity is enforced through the
        handle, not asked of the caller: mutating ops take the peer's write lock
        via PeerHandle::Write(), the only lock that keeps head, tail and the next
        links consistent as one structure. The pending slots' own RW locks are
        unused; a slot's bytes are only touched while it is unreachable (filled
        before linking, read after detaching). */
    namespace pending
    {
        /** Copies the packet into a fresh pending slot, marks it active and
            appends it. The caller keeps ownership of `packet`; its slot is not
            consumed. The list is untouched on failure.

            @return InvalidState on a failed handle, PoolExhausted when the
            pending pool is dry, PacketTooLarge when the payload exceeds the wire
            maximum. */
        [[nodiscard]] common::Error Push(common::collections::SlotPool& pool,
                                         PeerHandle& peer,
                                         const PacketSlot& packet,
                                         bool requireAuth = false,
                                         bool retained = false);

        /** Detaches the oldest pending packet, marks it inactive and returns its
            slot index, or SlotPool::INVALID when the list is empty (or the handle
            failed). The detached slot belongs to the caller alone until it is
            Released back to the pool: read, send, then release. */
        [[nodiscard]] uint32_t PopFront(common::collections::SlotPool& pool,
                                        PeerHandle& peer);

        /** Releases every pending packet without sending. Leaves the list empty. */
        void Clear(common::collections::SlotPool& pool, PeerHandle& peer);

        /** Walks the list under the peer's read lock. For tests and metrics, not
            hot-path decisions. */
        [[nodiscard]] uint32_t Count(const common::collections::SlotPool& pool,
                                     PeerHandle& peer);
    }
}
