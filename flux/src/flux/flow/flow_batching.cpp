#include <flux/flow/flow_table.h>

#include <cstring>

#include <flux/socket/packet_slot.h>
#include <flux/wire/batch.h>

/** The open batch on a sending association: what may join it, what it costs,
    and handing the finished bytes to the caller that will seal them.

    Separate from flow_table.cpp because this is send-side work and that file's
    other half is delivery. The byte layout itself is not here either: that is
    wire/batch.cpp, which knows nothing about associations or locks. What lives
    here is the middle, the part that takes the association's lock, asks the
    layout whether a message fits, and keeps the cursor fields on the slot in
    step with the bytes. */

namespace bcp::flux
{
    FlowTable::BatchAdmit FlowTable::AppendToBatch(uint32_t assocSlot, const PacketSlot& packet,
                                                   uint16_t limit) noexcept
    {
        const size_t header = packet.ContentOffset();
        if (header > packet.dataSize) return BatchAdmit::Rejected;

        // dataSize less the header, NOT ContentLength: this packet has been
        // built but not sealed, and the seal is what appends the tag, so the
        // trailer ContentLength subtracts is not there yet. Using it would trim
        // the last sixteen bytes off every message.
        const size_t content = packet.dataSize - header;
        if (content == 0 || content > UINT16_MAX) return BatchAdmit::Rejected;

        // The seal will append that tag to whatever the batch holds, so the
        // room it needs comes out of the limit here rather than being
        // discovered when the sealed packet turns out to be too long.
        if (limit > internal::MAX_WIRE_PACKET_SIZE) limit = internal::MAX_WIRE_PACKET_SIZE;
        const uint16_t trailer = packet.IsSecure() ? internal::WIRE_TAG_SIZE : 0;
        if (limit <= trailer) return BatchAdmit::Rejected;
        limit = static_cast<uint16_t>(limit - trailer);

        OutAssociation* flow = reinterpret_cast<OutAssociation*>(
            outAssocPool_.WriteLock(assocSlot));
        if (!flow) return BatchAdmit::Rejected;

        if (flow->openBatchInFlight)
        {
            // A flush has this batch and has not yet said whether it went. This
            // message cannot join it, so it takes the ordinary path and the
            // next batch starts clean.
            outAssocPool_.UnlockWrite(assocSlot);
            return BatchAdmit::Rejected;
        }

        BatchAdmit result;
        uint8_t* buffer = flow->OpenBatch();
        if (flow->openBatchUsed == 0)
        {
            // Nothing open. This packet's own framing becomes the batch's, so
            // the whole thing is copied and the first message sits bare behind
            // it, exactly as an unbatched packet would look.
            if (header + content > limit)
            {
                result = BatchAdmit::Rejected;   // cannot fit even on its own
            }
            else
            {
                std::memcpy(buffer, packet.data, header + content);
                flow->openBatchHeader   = static_cast<uint16_t>(header);
                flow->openBatchUsed     = static_cast<uint16_t>(header + content);
                flow->openBatchCount    = 1;
                flow->openBatchFirstLen = static_cast<uint16_t>(content);
                result = BatchAdmit::Appended;
            }
        }
        else
        {
            wire::BatchCursor cursor{
                buffer + flow->openBatchHeader,
                static_cast<uint16_t>(flow->openBatchUsed - flow->openBatchHeader),
                flow->openBatchCount,
                flow->openBatchFirstLen,
                static_cast<uint16_t>(limit - flow->openBatchHeader)
            };

            if (!wire::BatchAppend(cursor, packet.data + header,
                                   static_cast<uint16_t>(content)))
            {
                // Full. Leave the batch exactly as it is so the caller can send
                // it, then offer this message again into the empty one.
                result = BatchAdmit::Sealed;
            }
            else
            {
                flow->openBatchUsed  = static_cast<uint16_t>(flow->openBatchHeader + cursor.used);
                flow->openBatchCount = cursor.count;
                // Second message onward: the content is a list now, and the
                // controller has to say so or the far side reads it as one
                // message with rubbish appended.
                buffer[0] = static_cast<uint8_t>(buffer[0] | internal::WIRE_CTRL_BATCH);
                result = BatchAdmit::Appended;
            }
        }

        outAssocPool_.UnlockWrite(assocSlot);
        return result;
    }

    uint16_t FlowTable::TakeBatch(uint32_t assocSlot, uint8_t* out, uint16_t capacity,
                                  FlowMode& outMode) noexcept
    {
        if (!out) return 0;

        OutAssociation* flow = reinterpret_cast<OutAssociation*>(
            outAssocPool_.WriteLock(assocSlot));
        if (!flow) return 0;

        outMode = flow->mode;
        uint16_t written = 0;
        if (flow->openBatchUsed != 0 && flow->openBatchUsed <= capacity
            && !flow->openBatchInFlight)
        {
            // Copied, not consumed. The batch stays until the caller reports
            // the send actually happened, because an admission refused at the
            // flush would otherwise throw away messages the caller was told had
            // been accepted.
            std::memcpy(out, flow->OpenBatch(), flow->openBatchUsed);
            written = flow->openBatchUsed;
            flow->openBatchInFlight = true;   // no append may join it now
        }

        outAssocPool_.UnlockWrite(assocSlot);
        return written;
    }

    void FlowTable::FinishBatch(uint32_t assocSlot, uint16_t expectedUsed, bool sent) noexcept
    {
        OutAssociation* flow = reinterpret_cast<OutAssociation*>(
            outAssocPool_.WriteLock(assocSlot));
        if (!flow) return;
        // No append can have grown it, since they are refused while in flight,
        // so the size still matching is an invariant rather than a hope.
        if (sent && flow->openBatchUsed == expectedUsed)
        {
            flow->openBatchUsed     = 0;
            flow->openBatchHeader   = 0;
            flow->openBatchCount    = 0;
            flow->openBatchFirstLen = 0;
        }
        flow->openBatchInFlight = false;
        outAssocPool_.UnlockWrite(assocSlot);
    }

    bool FlowTable::PeekBatch(uint32_t assocSlot, FlowMode& outMode) noexcept
    {
        const OutAssociation* flow = reinterpret_cast<const OutAssociation*>(
            outAssocPool_.ReadLock(assocSlot));
        if (!flow) return false;
        const bool open = flow->openBatchUsed != 0;
        outMode = flow->mode;
        outAssocPool_.UnlockRead(assocSlot);
        return open;
    }
}
