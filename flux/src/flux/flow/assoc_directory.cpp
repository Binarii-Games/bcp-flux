#include <flux/flow/flow_table.h>

#include <flux/socket/packet_slot.h>

/** Finding, publishing and erasing an association in a peer's directory.

    Each peer has one small fixed table per direction, and a lookup walks it
    linearly because the tables are short enough that a hash would cost more
    than it saved. Nothing here knows what an association means. It maps a flow
    id to a slot index and back, which is the only reason the send and receive
    paths can reach their state without holding a table-wide lock. */

namespace bcp::flux
{

    FlowDirEntry* FlowTable::OutDirFor(uint32_t peerSlot) noexcept
    {
        return outAssocDir_.get() + static_cast<size_t>(peerSlot) * maxOutAssocPerPeer_;
    }

    FlowDirEntry* FlowTable::InDirFor(uint32_t peerSlot) noexcept
    {
        return inAssocDir_.get() + static_cast<size_t>(peerSlot) * maxInAssocPerPeer_;
    }

    /** The directory scan every flow lookup shares.

        @return The entry's flow slot, or INVALID when the id is not published in
        this segment. */
    uint32_t FlowTable::FindFlowSlot(const FlowDirEntry* dir, uint32_t width,
                                     uint16_t flowId) noexcept
    {
        for (uint32_t i = 0; i < width; ++i)
        {
            if (dir[i].flowSlot == common::collections::SlotPool::INVALID) continue;
            if (dir[i].flowId == flowId) return dir[i].flowSlot;
        }
        return common::collections::SlotPool::INVALID;
    }

    /** One scan that both rejects a duplicate id and finds the first free entry,
        publishing the already-leased slot on success.

        @return INVALID when the id is already published (duplicate); `width` when
        there is no free entry (directory full); otherwise the index written.
        @pre Caller holds the peer write lock, the directory's guard. */
    uint32_t FlowTable::InsertFlowSlot(FlowDirEntry* dir, uint32_t width,
                                       uint16_t flowId, uint32_t flowSlot) noexcept
    {
        uint32_t freeAt = width;
        for (uint32_t i = 0; i < width; ++i)
        {
            if (dir[i].flowSlot == common::collections::SlotPool::INVALID)
            {
                if (freeAt == width) freeAt = i;
                continue;
            }
            if (dir[i].flowId == flowId)
                return common::collections::SlotPool::INVALID;   // duplicate
        }
        if (freeAt == width)
            return width;   // directory full
        dir[freeAt] = FlowDirEntry{ flowId, 0, flowSlot };
        return freeAt;
    }

    /** Find-and-clear: unpublish the entry that points at `flowSlot`. The slot is
        unique in the segment, so matching on it alone hits a single entry. */
    void FlowTable::EraseFlowSlot(FlowDirEntry* dir, uint32_t width,
                                  uint32_t flowSlot) noexcept
    {
        for (uint32_t i = 0; i < width; ++i)
        {
            if (dir[i].flowSlot == flowSlot)
            {
                dir[i] = FlowDirEntry{ internal::INVALID_FLOW_ID, 0,
                                       common::collections::SlotPool::INVALID };
                return;
            }
        }
    }

    uint32_t FlowTable::FindFlowById(uint16_t flowId) noexcept
    {
        // A free slot carries INVALID_FLOW_ID, written at Init and restored on
        // close. Zero is a legal flow id, so the sentinel cannot be the pool's
        // zeroing.
        if (flowId == internal::INVALID_FLOW_ID)
            return common::collections::SlotPool::INVALID;

        for (uint32_t slot = 0; slot < flowPool_.GetCapacity(); ++slot)
        {
            const Flow* flow = reinterpret_cast<const Flow*>(flowPool_.ReadLock(slot));
            const bool match = flow->flowId == flowId;
            flowPool_.UnlockRead(slot);
            if (match) return slot;
        }
        return common::collections::SlotPool::INVALID;
    }

    void FlowTable::LinkAssociation(uint32_t flowSlot, uint32_t assocSlot) noexcept
    {
        Flow* flow = reinterpret_cast<Flow*>(flowPool_.WriteLock(flowSlot));
        OutAssociation* assoc = reinterpret_cast<OutAssociation*>(
            outAssocPool_.WriteLock(assocSlot));

        assoc->flowSlot   = flowSlot;
        assoc->nextInFlow = flow->firstAssoc;
        flow->firstAssoc  = assocSlot;

        outAssocPool_.UnlockWrite(assocSlot);
        flowPool_.UnlockWrite(flowSlot);
    }

    void FlowTable::UnlinkAssociation(uint32_t flowSlot, uint32_t assocSlot) noexcept
    {
        if (flowSlot >= flowPool_.GetCapacity())
            return;

        Flow* flow = reinterpret_cast<Flow*>(flowPool_.WriteLock(flowSlot));

        uint32_t prev = common::collections::SlotPool::INVALID;
        uint32_t scan = flow->firstAssoc;
        while (scan != common::collections::SlotPool::INVALID && scan != assocSlot)
        {
            const OutAssociation* node = reinterpret_cast<const OutAssociation*>(
                outAssocPool_.ReadLock(scan));
            const uint32_t next = node->nextInFlow;
            outAssocPool_.UnlockRead(scan);
            prev = scan;
            scan = next;
        }

        if (scan == assocSlot)
        {
            OutAssociation* node = reinterpret_cast<OutAssociation*>(
                outAssocPool_.WriteLock(assocSlot));
            const uint32_t next = node->nextInFlow;
            node->nextInFlow = common::collections::SlotPool::INVALID;
            node->flowSlot   = common::collections::SlotPool::INVALID;
            outAssocPool_.UnlockWrite(assocSlot);

            if (prev == common::collections::SlotPool::INVALID)
            {
                flow->firstAssoc = next;
            }
            else
            {
                OutAssociation* before = reinterpret_cast<OutAssociation*>(
                    outAssocPool_.WriteLock(prev));
                before->nextInFlow = next;
                outAssocPool_.UnlockWrite(prev);
            }
        }

        flowPool_.UnlockWrite(flowSlot);
    }
}
