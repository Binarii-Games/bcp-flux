#include <common/log.h>
#include <flux/internal/constants.h>
#include <flux/socket/socket.h>
#include <flux/wire/packet_builder.h>
#include <flux/socket/socket_sender.h>
#include <flux/socket/packet_slot.h>

namespace bcp::flux::wire
{
    // --- Builder ---
    namespace
    {
        /** A second, different choice is a conflict rather than a last-wins
            race: the caller believes both, and only one can be true. */
        bool Conflicts(bool chosen, PacketBuilder::Security have,
                       PacketBuilder::Security want) noexcept
        {
            return chosen && have != want;
        }
    }

    PacketBuilder& PacketBuilder::Unsecured()
    {
        if (Conflicts(securityChosen_, security_, Security::Unsecured))
            failReason_ = common::Error::InvalidParam;
        security_      = Security::Unsecured;
        securityChosen_ = true;
        return *this;
    }

    PacketBuilder& PacketBuilder::MacOnly()
    {
        if (Conflicts(securityChosen_, security_, Security::MacOnly))
            failReason_ = common::Error::InvalidParam;
        security_      = Security::MacOnly;
        securityChosen_ = true;
        return *this;
    }

    namespace
    {
        /** The header every packet opens with, identical for flow and non-flow
            traffic: controller byte, reserved secure header, encrypted channel
            byte. hasFlow only sets a controller bit here; the flow's id and
            sequence number are reserved by the caller, since they sit after the
            channel byte. */
        bool WriteCommonHeader(PacketSlotWriter& writer, PacketBuilder::Security level,
                               bool tagged, bool hasFlow)
        {
            const bool secure = level != PacketBuilder::Security::Unsecured;

            uint8_t controller = secure ? 0x00 : ToByte(Controls::CTRL_UNSECURE);
            if (level == PacketBuilder::Security::MacOnly)
                controller |= ToByte(Controls::CTRL_MACONLY);
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

    PacketBuilder& PacketBuilder::NoFlow()
    {
        target_ = Target::NoFlow;
        return *this;
    }

    PacketBuilder& PacketBuilder::WithFlow(const FlowHandle& flow, FlowPart part)
    {
        target_ = Target::Flow;
        flow_   = &flow;
        part_   = part;
        return *this;
    }

    PacketContentStage PacketBuilder::Begin()
    {
        if (!socket_)
            return PacketContentStage(failReason_);
        if (spent_)
            return PacketContentStage(common::Error::InvalidState);
        if (target_ == Target::Unset)
            return PacketContentStage(common::Error::InvalidState);
        if (failReason_ != common::Error::Ok)
            return PacketContentStage(failReason_);
        spent_ = true;

        if (target_ == Target::NoFlow)
        {
            common::Result<PacketSlotWriter> result = socket_->AcquireKernelWriter();
            if (result.isErr())
                return PacketContentStage(result.error);
            PacketSlotWriter writer = result.Take();

            // User traffic: the internal bit stays clear, or Poll would consume
            // the packet as protocol traffic instead of delivering it.
            const bool secure = security_ != Security::Unsecured;
            if (!WriteCommonHeader(writer, security_, secure && tagged_, false))
                return PacketContentStage(common::Error::BufferFull);

            return PacketContentStage(*sender_, std::move(writer), respondTo_);
        }

        const FlowHandle& flow = *flow_;

        // Refused here rather than on the wire, so a caller framing a message
        // on a mode that cannot carry one learns at the send that asked for it.
        FlowMode mode{};
        if (part_ != FlowPart::Whole
         && (!socket_->FlowModeOf(flow, mode) || !FlowPartAllowed(mode, part_)))
            return PacketContentStage(common::Error::InvalidParam);

        // The pool depends on the flow's mode: a reliable flow's body is its own
        // retransmit source and must outlive the send, so the socket resolves
        // the flow and hands back a writer over the right slot.
        common::Result<PacketSlotWriter> result = socket_->AcquireFlowWriter(flow);
        if (result.isErr())
            return PacketContentStage(result.error);
        PacketSlotWriter writer = result.Take();

        // A flow needs its sequence to be trustworthy. MacOnly keeps it inside
        // the authenticated range, so it is readable but not forgeable, and a
        // flow rides one safely. Unsecured has no tag at all, so anyone could
        // mint a packet naming any sequence and poison the ordering.
        if (security_ == Security::Unsecured)
            return PacketContentStage(common::Error::InvalidParam);

        if (!WriteCommonHeader(writer, security_, tagged_, true))
            return PacketContentStage(common::Error::BufferFull);

        // The stored byte carries the mode and the generation, which are fixed
        // for the flow's lifetime. The framing bits belong to this packet
        // alone, so they are laid over it here rather than at open.
        uint8_t flowData = flow.FlowData();
        if (part_ == FlowPart::First || part_ == FlowPart::Middle) flowData |= FLOW_PART_MORE;
        if (part_ == FlowPart::Middle || part_ == FlowPart::Last)  flowData |= FLOW_PART_CONT;

        // PutU32(0) reserves the sequence bytes; PreProcessOut stamps them.
        if (!writer.PutU16(flow.Id()) || !writer.PutU32(0) || !writer.PutU8(flowData))
            return PacketContentStage(common::Error::BufferFull);

        return PacketContentStage(*sender_, std::move(writer), respondTo_);
    }

    // Each takes the slot, writes the header, puts, and hands the stage on. The
    // stage owns a writer and is move-only, so it is named rather than chained
    // straight through.
    PacketContentStage PacketBuilder::PutU8(uint8_t in)
    { PacketContentStage stage = Begin(); stage.PutU8(in); return stage; }
    PacketContentStage PacketBuilder::PutU16(uint16_t in)
    { PacketContentStage stage = Begin(); stage.PutU16(in); return stage; }
    PacketContentStage PacketBuilder::PutU32(uint32_t in)
    { PacketContentStage stage = Begin(); stage.PutU32(in); return stage; }
    PacketContentStage PacketBuilder::PutU64(uint64_t in)
    { PacketContentStage stage = Begin(); stage.PutU64(in); return stage; }
    PacketContentStage PacketBuilder::PutBytes(const uint8_t* data, size_t len)
    { PacketContentStage stage = Begin(); stage.PutBytes(data, len); return stage; }

    common::Error PacketBuilder::Send(Address address)        { PacketContentStage stage = Begin(); return stage.Send(address); }
    common::Error PacketBuilder::SendSecured(Address address) { PacketContentStage stage = Begin(); return stage.SendSecured(address); }
    common::Error PacketBuilder::Respond()                    { PacketContentStage stage = Begin(); return stage.Respond(); }
    common::Error PacketBuilder::RespondSecured()             { PacketContentStage stage = Begin(); return stage.RespondSecured(); }

    // --- Content stage ---
    PacketContentStage& PacketContentStage::PutU8(uint8_t in)
    {
        if (!writer_.PutU8(in)) Fail(common::Error::TooLarge);
        return *this;
    }

    PacketContentStage& PacketContentStage::PutU16(uint16_t in)
    {
        if (!writer_.PutU16(in)) Fail(common::Error::TooLarge);
        return *this;
    }

    PacketContentStage& PacketContentStage::PutU32(uint32_t in)
    {
        if (!writer_.PutU32(in)) Fail(common::Error::TooLarge);
        return *this;
    }

    PacketContentStage& PacketContentStage::PutU64(uint64_t in)
    {
        if (!writer_.PutU64(in)) Fail(common::Error::TooLarge);
        return *this;
    }

    PacketContentStage& PacketContentStage::PutBytes(const uint8_t* data, size_t len)
    {
        if (!writer_.PutBytes(data, len)) Fail(common::Error::TooLarge);
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