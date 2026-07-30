#pragma once

#include <cstdint>

#include <common/error.h>

#include <flux/flow/flow.h>
#include <flux/internal/constants.h>

namespace bcp::flux
{
    /** The app's reference to a flow it opened: a key, not a lease. It names
        the flow, never a target, so the same handle addresses every peer the
        flow is sent to. The receiving side of a remote's flow is Flux-internal
        and has no handle.

        It holds no lock and keeps nothing alive; the flow lives in the socket
        until CloseFlow, so it is cheap to hold for the flow's whole life. Every
        operation goes through the socket (GetFlowState, CloseFlow, sending),
        which checks slot + epoch: a handle outliving its flow misses, never
        reaching a recycled slot's new tenant, even when the id is reopened.

        Move-only so the flow keeps one referent; a moved-from handle is failed
        and matches nothing. */
    class FlowHandle
    {
    private:
        uint32_t slot_{UINT32_MAX};
        uint32_t epoch_{0};
        uint16_t flowId_{internal::INVALID_FLOW_ID};
        uint8_t  flowData_{0};   ///< the wire byte: the mode, fixed at open
        common::Error failReason_{common::Error::InvalidState};

    public:
        FlowHandle() = default;
        FlowHandle(uint32_t slot, uint32_t epoch, uint16_t flowId, uint8_t flowData)
            : slot_(slot), epoch_(epoch), flowId_(flowId), flowData_(flowData),
              failReason_(common::Error::Ok) {}
        explicit FlowHandle(common::Error failReason)
            : failReason_(failReason) {}

        FlowHandle(const FlowHandle&) = delete;
        FlowHandle& operator=(const FlowHandle&) = delete;

        FlowHandle(FlowHandle&& o) noexcept { Steal(o); }
        FlowHandle& operator=(FlowHandle&& o) noexcept
        {
            if (this != &o) Steal(o);
            return *this;
        }

        [[nodiscard]] bool Failed() const { return failReason_ != common::Error::Ok; }
        [[nodiscard]] common::Error FailReason() const { return failReason_; }

        [[nodiscard]] uint16_t Id() const { return flowId_; }
        /** The encoded mode this flow stamps on every packet. Carried here
            because it is fixed for the flow's whole life, so the builder can
            stamp it without taking the flow's lock. */
        [[nodiscard]] uint8_t FlowData() const { return flowData_; }
        [[nodiscard]] uint32_t Slot() const { return slot_; }
        [[nodiscard]] uint32_t Epoch() const { return epoch_; }

    private:
        void Steal(FlowHandle& o) noexcept
        {
            slot_ = o.slot_; epoch_ = o.epoch_; flowId_ = o.flowId_;
            flowData_ = o.flowData_;
            failReason_ = o.failReason_;
            o.slot_ = UINT32_MAX; o.epoch_ = 0;
            o.flowId_ = internal::INVALID_FLOW_ID;
            o.failReason_ = common::Error::InvalidState;
        }
    };
}
