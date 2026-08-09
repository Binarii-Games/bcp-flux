#include <flux/socket/socket_events.h>

namespace bcp::flux
{
    common::Error EventTable::Init(EventHook hook, void* context, uint32_t subscribed,
                                   uint32_t outSlots, uint32_t inSlots,
                                   uint32_t peerSlots, uint32_t lanes)
    {
        Shutdown();

        // Nothing to call or nothing asked for. Both mean the same thing to a
        // socket that wants no events, and neither is a failure.
        if (!hook || subscribed == 0) return common::Error::Ok;
        if (lanes == 0) return common::Error::InvalidParam;

        pending_ = std::make_unique<std::atomic<uint32_t>[]>(lanes);
        if (!pending_) return common::Error::AllocFailed;
        laneCount_ = lanes;

        if (outSlots > 0)
        {
            outFlows_ = std::make_unique<Entry[]>(outSlots);
            if (!outFlows_) return common::Error::AllocFailed;
            outCount_ = outSlots;
        }
        if (inSlots > 0)
        {
            inFlows_ = std::make_unique<Entry[]>(inSlots);
            if (!inFlows_) return common::Error::AllocFailed;
            inCount_ = inSlots;
        }
        if (peerSlots > 0)
        {
            peers_ = std::make_unique<Entry[]>(peerSlots);
            if (!peers_) return common::Error::AllocFailed;
            peerCount_ = peerSlots;
        }

        hook_       = hook;
        context_    = context;
        subscribed_ = subscribed;
        return common::Error::Ok;
    }

    void EventTable::Shutdown() noexcept
    {
        // Cleared before the rows go, so a Record arriving late finds no hook
        // and returns rather than reaching freed entries.
        hook_       = nullptr;
        context_    = nullptr;
        subscribed_ = 0;

        outFlows_.reset();
        inFlows_.reset();
        peers_.reset();
        pending_.reset();
        outCount_  = 0;
        inCount_   = 0;
        peerCount_ = 0;
        laneCount_ = 0;
    }

    EventTable::Entry* EventTable::RowFor(EventScope scope, uint32_t slot) noexcept
    {
        if (scope == EventScope::OUT_FLOW)
            return slot < outCount_ ? &outFlows_[slot] : nullptr;
        if (scope == EventScope::IN_FLOW)
            return slot < inCount_ ? &inFlows_[slot] : nullptr;
        return slot < peerCount_ ? &peers_[slot] : nullptr;
    }

    bool EventTable::Record(EventScope scope, uint32_t slot, uint32_t lane,
                            SocketEvent event, const Address& peer,
                            uint16_t flowId) noexcept
    {
        if (!hook_) return false;

        const uint32_t bit = ToBits(event);
        if ((subscribed_ & bit) == 0) return false;
        if (lane >= laneCount_) return false;

        Entry* entry = RowFor(scope, slot);
        if (!entry) return false;

        uint32_t current = entry->bits.load(std::memory_order_acquire);
        for (;;)
        {
            if (current != 0)
            {
                // Already carrying something for this same occupant, because a
                // slot cannot change hands while its entry is full. Fold this in
                // and leave the identity alone: someone may be reading it.
                if (entry->bits.compare_exchange_weak(current, current | bit,
                                                      std::memory_order_release,
                                                      std::memory_order_acquire))
                    return true;
                continue;
            }

            entry->peer   = peer;
            entry->flowId = flowId;
            entry->lane   = lane;
            if (entry->bits.compare_exchange_weak(current, bit,
                                                  std::memory_order_release,
                                                  std::memory_order_acquire))
            {
                pending_[lane].fetch_add(1, std::memory_order_relaxed);
                return true;
            }
        }
    }

    uint32_t EventTable::DispatchRow(Entry* row, uint32_t count, EventScope scope,
                                     uint32_t lane, uint32_t wanted,
                                     SlotDoneFn done, void* doneContext) noexcept
    {
        uint32_t taken = 0;
        for (uint32_t i = 0; i < count && taken < wanted; ++i)
        {
            Entry& entry = row[i];

            if (entry.bits.load(std::memory_order_acquire) == 0) continue;
            if (entry.lane != lane) continue;   // some other thread's peers

            // Read before the take. The bits are set, so nothing is writing
            // these, and clearing them is what lets the next occupant write
            // here.
            const Address  peer   = entry.peer;
            const uint16_t flowId = entry.flowId;

            const uint32_t held = entry.bits.exchange(0, std::memory_order_acq_rel);
            if (held == 0) continue;

            pending_[lane].fetch_sub(1, std::memory_order_relaxed);
            ++taken;

            const EventInfo info(held, peer, flowId);
            hook_(context_, info);

            // After the handler, so the association it names is still there for
            // whatever the handler asked the socket about.
            if (done) done(doneContext, scope, i);
        }
        return taken;
    }

    void EventTable::Dispatch(uint32_t lane, SlotDoneFn done, void* doneContext) noexcept
    {
        if (!hook_ || lane >= laneCount_) return;

        // The count is what stops the walk early: a socket with thousands of
        // association slots and one thing to report should not read every one
        // of them to find it. Anything recorded after this read goes out on the
        // next poll, which is already true of anything recorded after the walk
        // has passed its slot.
        const uint32_t wanted = pending_[lane].load(std::memory_order_acquire);
        if (wanted == 0) return;

        uint32_t taken = DispatchRow(outFlows_.get(), outCount_, EventScope::OUT_FLOW,
                                     lane, wanted, done, doneContext);
        if (taken < wanted)
            taken += DispatchRow(inFlows_.get(), inCount_, EventScope::IN_FLOW,
                                 lane, wanted - taken, done, doneContext);
        if (taken < wanted)
            (void)DispatchRow(peers_.get(), peerCount_, EventScope::PEER,
                              lane, wanted - taken, done, doneContext);
    }
}
