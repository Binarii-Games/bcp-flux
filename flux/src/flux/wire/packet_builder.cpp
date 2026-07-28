#include <common/log.h>
#include <flux/internal/constants.h>
#include <flux/socket/socket.h>
#include <flux/wire/packet_builder.h>
#include <flux/socket/socket_sender.h>
#include <flux/socket/packet_slot.h>

namespace bcp::flux::wire
{
    // --- Builder ---
    PacketBuilder& PacketBuilder::Unsecured()
    {
        secure_ = false;
        return *this;
    }

    namespace
    {
        /** The header every packet opens with, identical for flow and non-flow
            traffic: controller byte, reserved secure header, encrypted channel
            byte. hasFlow only sets a controller bit here; the flow's id and
            sequence number are reserved by the caller, since they sit after the
            channel byte. */
        bool WriteCommonHeader(PacketSlotWriter& writer, bool secure, bool tagged,
                               bool hasFlow)
        {
            uint8_t controller = secure ? 0x00 : ToByte(Controls::CTRL_UNSECURE);
            if (tagged)  controller |= ToByte(Controls::CTRL_TAGGED);
            if (hasFlow) controller |= ToByte(Controls::CTRL_HAS_FLOW);
            if (!writer.PutU8(controller))
                return false;

            // Tag, nonce, and (when tagged) the peer tag ride between the
            // controller and the content; stamped at send time, once the peer's
            // counter, key, and current tag are known.
            if (secure && !writer.ReserveSecureHeader(tagged))
                return false;

            // First plaintext byte of every secure packet: the in-band channel.
            // App data is 0; control traffic uses other values. Encrypted, so an
            // observer can never tell which kind a packet is.
            if (secure && !writer.PutU8(internal::SECURE_CHANNEL_APP))
                return false;

            return true;
        }
    }

    PacketContentStage PacketBuilder::NoFlow()
    {
        if (!socket_)
            return PacketContentStage(failReason_);
        if (spent_)
            return PacketContentStage(common::Error::InvalidState);
        spent_ = true;

        common::Result<PacketSlotWriter> result = socket_->AcquireKernelWriter();
        if (result.isErr())
            return PacketContentStage(result.error);
        PacketSlotWriter writer = result.Take();

        // User traffic: the internal bit stays clear, or Poll would consume
        // the packet as protocol traffic instead of delivering it.
        if (!WriteCommonHeader(writer, secure_, secure_ && tagged_, false))
            return PacketContentStage(common::Error::BufferFull);

        return PacketContentStage(*sender_, std::move(writer), respondTo_);
    }

    PacketContentStage PacketBuilder::WithFlow(const FlowHandle& flow)
    {
        if (!socket_)
            return PacketContentStage(failReason_);
        if (spent_)
            return PacketContentStage(common::Error::InvalidState);
        spent_ = true;

        // The pool depends on the flow's mode: a reliable flow's body is its own
        // retransmit source and must outlive the send, so the socket resolves
        // the flow and hands back a writer over the right slot.
        common::Result<PacketSlotWriter> result = socket_->AcquireFlowWriter(flow);
        if (result.isErr())
            return PacketContentStage(result.error);
        PacketSlotWriter writer = result.Take();

        // Flow traffic is always secure: the id and sequence number are Flux's
        // own framing and belong under the encryption with the rest.
        if (!secure_)
            return PacketContentStage(common::Error::InvalidParam);

        if (!WriteCommonHeader(writer, true, tagged_, true))
            return PacketContentStage(common::Error::BufferFull);

        // The id and sequence number follow the channel byte. The id is known
        // now; the sequence number is assigned at send time, under the flow's
        // lock, so packets leave in the order their numbers were handed out.
        if (!writer.PutU16(flow.Id()) || !writer.PutU32(0))
            return PacketContentStage(common::Error::BufferFull);

        return PacketContentStage(*sender_, std::move(writer), respondTo_);
    }

    // --- Content stage ---
    PacketContentStage& PacketContentStage::PutU8(uint8_t in)
    {
        if (!writer_.PutU8(in)) failed_ = true;
        return *this;
    }

    PacketContentStage& PacketContentStage::PutU16(uint16_t in)
    {
        if (!writer_.PutU16(in)) failed_ = true;
        return *this;
    }

    PacketContentStage& PacketContentStage::PutU32(uint32_t in)
    {
        if (!writer_.PutU32(in)) failed_ = true;
        return *this;
    }

    PacketContentStage& PacketContentStage::PutU64(uint64_t in)
    {
        if (!writer_.PutU64(in)) failed_ = true;
        return *this;
    }

    PacketContentStage& PacketContentStage::PutBytes(const uint8_t* data, size_t len)
    {
        if (!writer_.PutBytes(data, len)) failed_ = true;
        return *this;
    }

    common::Error PacketContentStage::Send(Address address)
    {
        if (failed_) return failReason_;
        writer_.WriteAddress(address);
        return sender_->Send(std::move(writer_).ExtractHandle());
    }

    common::Error PacketContentStage::SendSecured(Address address)
    {
        if (failed_) return failReason_;
        writer_.WriteAddress(address);
        return sender_->Send(std::move(writer_).ExtractHandle(), true);
    }

    common::Error PacketContentStage::Respond()
    {
        if (failed_) return failReason_;
        if (!respondTo_.IsSet()) return common::Error::InvalidState;
        return Send(respondTo_);
    }

    common::Error PacketContentStage::RespondSecured()
    {
        if (failed_) return failReason_;
        if (!respondTo_.IsSet()) return common::Error::InvalidState;
        return SendSecured(respondTo_);
    }
}