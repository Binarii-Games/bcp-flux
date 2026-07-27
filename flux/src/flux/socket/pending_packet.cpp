#include <flux/socket/pending_packet.h>

#include <cassert>
#include <cstring>

#include <flux/internal/constants.h>

namespace bcp::flux::pending
{
    using common::collections::SlotPool;

    common::Error Push(SlotPool& pool, PeerHandle& peer, const PacketSlot& packet, bool requireAuth)
    {
        if (packet.dataSize > internal::MAX_WIRE_PACKET_SIZE)
            return common::Error::PacketTooLarge;

        Peer* p = peer.Write();
        if (!p)
            return common::Error::InvalidState;

        const uint32_t idx = pool.Acquire();
        if (idx == SlotPool::INVALID)
            return common::Error::PoolExhausted;

        auto* slot = reinterpret_cast<PendingPacket*>(pool.GetSlotPtr(idx));
        assert(slot->active == 0);
        slot->next        = SlotPool::INVALID;
        slot->requireAuth = requireAuth ? 1 : 0;
        slot->address     = packet.address;
        slot->dataSize    = packet.dataSize;
        std::memcpy(slot->data, packet.data, packet.dataSize);
        slot->active      = 1;

        if (p->pendingTail == SlotPool::INVALID)
        {
            p->pendingHead = idx;
        }
        else
        {
            auto* tail = reinterpret_cast<PendingPacket*>(pool.GetSlotPtr(p->pendingTail));
            tail->next = idx;
        }
        p->pendingTail = idx;

        return common::Error::Ok;
    }

    uint32_t PopFront(SlotPool& pool, PeerHandle& peer)
    {
        Peer* p = peer.Write();
        if (!p)
            return SlotPool::INVALID;

        const uint32_t idx = p->pendingHead;
        if (idx == SlotPool::INVALID)
            return SlotPool::INVALID;

        auto* slot = reinterpret_cast<PendingPacket*>(pool.GetSlotPtr(idx));
        assert(slot->active == 1);
        p->pendingHead = slot->next;
        if (p->pendingHead == SlotPool::INVALID)
            p->pendingTail = SlotPool::INVALID;
        slot->active = 0;

        return idx;
    }

    void Clear(SlotPool& pool, PeerHandle& peer)
    {
        uint32_t idx;
        while ((idx = PopFront(pool, peer)) != SlotPool::INVALID)
            pool.Release(idx);
    }

    uint32_t Count(const SlotPool& pool, PeerHandle& peer)
    {
        const Peer* p = peer.Read();
        if (!p)
            return 0;

        uint32_t n = 0;
        for (uint32_t idx = p->pendingHead; idx != SlotPool::INVALID; ++n)
            idx = reinterpret_cast<const PendingPacket*>(pool.GetSlotPtr(idx))->next;
        return n;
    }
}
