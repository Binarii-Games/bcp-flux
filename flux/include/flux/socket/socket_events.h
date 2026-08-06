#pragma once

#include <cstdint>

#include <atomic>
#include <memory>

#include <common/error.h>
#include <common/platform.h>

#include <flux/address.h>
#include <flux/internal/constants.h>

namespace bcp::flux
{
    /** Things the socket can tell an application about. Bit values, because one
        entity can have several happen to it between two polls and they arrive
        together.

        Nothing here is a question. Every one of these describes something that
        already happened, so a handler that does nothing at all leaves the
        socket working exactly as it would have. */
    enum class SocketEvent : uint32_t
    {
        /** A remote created a receiving flow here. Nothing else reports this,
            so without it the only way to notice is to poll
            Socket::ReceivingFlowCount for every peer. */
        INCOMING_FLOW_OPENED  = (1u << 0),

        /** A peer would not accept a flow this socket opened, because it is at
            its cap for flows from here or it could not read the flow byte. It
            never held the flow and asking again on the same terms gets the same
            answer. */
        OUTGOING_FLOW_REFUSED = (1u << 1),

        /** A flow this socket opened stopped reaching one peer: a packet on it
            ran out of retransmits. It may have been running for hours, so
            unlike a refusal this says the path or the peer broke rather than
            that the flow was never wanted.

            Either way the flow stays open for every other peer, which is why
            both name an address. */
        OUTGOING_FLOW_LOST    = (1u << 2),

        /** A remote closed this flow id and opened it again. The association
            survives, but it numbers from one now and everything held against
            the old generation has been thrown away. An application reading
            that flow has to treat what comes next as a fresh start.

            There is no event for a remote merely closing a flow, because
            closing puts nothing on the wire and this side genuinely cannot
            know. It finds out here, or when the peer idles out. */
        INCOMING_FLOW_REOPENED = (1u << 3),

        /** The handshake completed and there is a session with this peer. */
        PEER_ESTABLISHED       = (1u << 4),

        /** This peer is gone: idled out, removed, or it stopped answering the
            handshake. The address is a copy, so it names a peer that no longer
            exists and looking it up finds nothing, which is the point. */
        PEER_LOST              = (1u << 5),

        /** This peer proved a new address and was rebound to it. Same session,
            same id, same counters. The address in the event is the new one. */
        PEER_MIGRATED          = (1u << 6),

        /** This peer changed what it says we may occupy of its receive pool,
            which is what bounds how much we can have in flight to it. */
        PEER_GRANT_CHANGED     = (1u << 7),

        /** We cut what this peer may occupy of OUR receive pool, because it
            kept holding buffer it never used. The other side of
            PEER_GRANT_CHANGED, and a decision this socket made rather than one
            it was told. */
        PEER_GRANT_CUT         = (1u << 8),

        /** A flow from this peer jammed: it held packets behind a gap the
            sender did not fill for the stall timeout, so the buffer was taken
            back. The flow itself survives and the sender resends into the same
            gap, so the cost is a round trip rather than data.

            Fires when the sweep finds a jam AND takes something back. A flow
            already reclaimed once and still stuck holds nothing, so it stays
            quiet until the sender puts something there again. The counter
            behind the grant cut follows the same rule, so the two never tell
            different stories.

            Peer-scoped rather than per flow, because that is how the count is
            already kept and because what an application does about it is about
            the peer. */
        PEER_FLOW_JAMMED       = (1u << 9),
    };

    constexpr uint32_t ToBits(SocketEvent e) noexcept { return static_cast<uint32_t>(e); }

    /** Which set of slots an event belongs to. Sending and receiving
        associations come from pools of their own, so their slot numbers are
        two separate spaces and each needs its own row of entries. */
    enum class EventScope : uint8_t
    {
        OUT_FLOW = 0,
        IN_FLOW  = 1,
        PEER     = 2,
    };

    /** What one entity had happen to it, handed over by Socket::Poll with
        nothing locked, so a handler can call straight back into the socket.

        It names the entity and carries nothing else. Everything it could carry
        is already readable through the ordinary calls, so a handler reads the
        state and gets the truth even when the event that woke it describes a
        moment that has since passed.

        The address and the flow id are copies taken when the event was
        recorded. Both may name something that no longer exists by the time the
        handler runs, and a peer that has gone reports as a failed handle while
        a closed flow reports as no flow. That is the same answer every other
        lookup in this library gives for something that is not there.

        Ask Has for each event rather than switching on one value. One call can
        report several events at once, which is what keeps the storage below
        bounded. */
    class EventInfo
    {
    private:
        uint32_t events_{0};
        Address  peer_{};
        uint16_t flowId_{internal::INVALID_FLOW_ID};

    public:
        EventInfo() = default;
        EventInfo(uint32_t events, const Address& peer, uint16_t flowId)
            : events_(events), peer_(peer), flowId_(flowId) {}

        [[nodiscard]] bool Has(SocketEvent e) const noexcept
        {
            return (events_ & ToBits(e)) != 0;
        }

        [[nodiscard]] const Address& Peer() const noexcept { return peer_; }
        [[nodiscard]] uint16_t Flow() const noexcept { return flowId_; }
    };

    /** Called once per entity that had something happen to it, from
        Socket::Poll. `context` is whatever was registered beside it and the
        library never reads it. */
    using EventHook = void (*)(void* context, const EventInfo& info);

    /** Called after each event is delivered, naming the slot it came from, so
        whoever owns that slot can stop holding it open. Internal, not something
        an application registers. */
    using SlotDoneFn = void (*)(void* context, EventScope scope, uint32_t slot);

    /** Where events wait until someone polls for them.

        One entry per association slot in a row per direction, and one per peer
        slot in a third, all sized at Init from the same counts the pools are. That is what makes delivery a
        property of the shape rather than of the traffic: every entity that
        exists occupies exactly one slot, so it has exactly one entry, and an
        event is only ever recorded while its entity still holds that slot.
        Per-peer limits decide how the pool is shared out and never how big it
        is, so raising one later cannot outgrow this.

        There is no queue and nothing to overflow. Several events on one entity
        between two polls merge into its one entry and arrive together.

        AND NOTHING IS EVER OVERWRITTEN, because an association carrying an
        unread event keeps its slot leased until that event is read. So the
        occupant of a slot is the same one its entry was written for, always,
        and there is no lost-event case to count. FlowTable owns that rule and
        does not know events exist: it is told a slot is emitting, and it is
        told when it stops.

        AN EVENT BELONGS TO THE SAME LANE ITS PEER'S PACKETS DO. Delivery is
        split into lanes so that everything from one peer reaches one thread,
        which is what lets an application hold per-peer state without locking
        it. An event dispatched on any other thread would break exactly that,
        so an entry is stamped with its peer's lane when it is recorded and only
        the thread holding that lane reports it. A lane is claimed by one thread
        at a time, so that claim is also what keeps two threads out of the same
        entry, and nothing else has to.

        WHAT MAY BE ADDED HERE. An event can arrive beside others and can arrive
        a poll late, so it can only ever be a nudge toward state that outlives
        it. Anything that needs an answer, or that has to arrive at an exact
        moment, is not an event and gets a call of its own. */
    class EventTable
    {
    private:
        /** `bits` is the OR of what has happened to this slot's occupant and
            not yet been reported. Zero means the entry is free.

            `lane`, `peer` and `flowId` are plain because of one rule: they are
            written only into a free entry and read only while a full one has
            its bits set. A writer and a reader therefore cannot be in them at
            the same moment. */
        struct Entry
        {
            std::atomic<uint32_t> bits{0};
            Address               peer{};
            uint32_t              lane{0};
            uint16_t              flowId{internal::INVALID_FLOW_ID};
        };

        std::unique_ptr<Entry[]> outFlows_;
        std::unique_ptr<Entry[]> inFlows_;
        std::unique_ptr<Entry[]> peers_;
        uint32_t outCount_{0};
        uint32_t inCount_{0};
        uint32_t peerCount_{0};

        /** Pending entries per lane, so a poll walks only until it has found
            what is waiting for it rather than to the end of both rows. */
        std::unique_ptr<std::atomic<uint32_t>[]> pending_;
        uint32_t laneCount_{0};

        EventHook hook_{nullptr};
        void*     context_{nullptr};
        uint32_t  subscribed_{0};

        [[nodiscard]] Entry* RowFor(EventScope scope, uint32_t slot) noexcept;
        uint32_t DispatchRow(Entry* row, uint32_t count, EventScope scope, uint32_t lane,
                             uint32_t wanted, SlotDoneFn done, void* doneContext) noexcept;

    public:
        EventTable() = default;
        ~EventTable() { Shutdown(); }

        EventTable(const EventTable&)            = delete;
        EventTable& operator=(const EventTable&) = delete;

        /** Allocates only when there is a hook to call, so a socket that
            registers nothing pays nothing. A null hook or an empty
            `subscribed` is not an error, it leaves the table inert and every
            Record a no-op.

            `outSlots` and `inSlots` are the association pool capacities, bulk
            included, since those pools share one slot numbering per direction,
            and `peerSlots` is the peer table's. `lanes` is the delivery lane
            count, which entries are grouped by.

            `subscribed` is the OR of the events the hook is called for.
            Anything outside it is never recorded. */
        [[nodiscard]] common::Error Init(EventHook hook, void* context, uint32_t subscribed,
                                         uint32_t outSlots, uint32_t inSlots,
                                         uint32_t peerSlots, uint32_t lanes);

        /** Idempotent, and safe to call on an inert table. */
        void Shutdown() noexcept;

        /** Marks `event` against the entity in `slot`, for the thread that will
            poll `lane`.

            @return true when the entry now holds something, so a dispatch is
                    coming for this slot. False when nothing was recorded, which
                    is an unregistered hook, an event outside the subscription,
                    or an index out of range. The caller uses it to decide
                    whether the slot has to be held for a delivery.

            Takes no lock of its own, so it is safe to call with a peer or
            association lock held, which is where most of what is worth
            reporting is decided. Never blocks and never allocates.

            @pre The entity still holds its slot. */
        [[nodiscard]] bool Record(EventScope scope, uint32_t slot, uint32_t lane,
                                  SocketEvent event, const Address& peer,
                                  uint16_t flowId) noexcept;

        /** Hands the hook everything pending for `lane` and empties it, calling
            `done` after each one so the caller can let go of a slot that was
            only still leased to keep its event alive.

            @pre The caller holds `lane` and no peer, flow or packet slot lock.
                 The lane claim is what keeps a second thread out of these
                 entries, and a handler is free to call back into the socket,
                 which would take the others. */
        void Dispatch(uint32_t lane, SlotDoneFn done, void* doneContext) noexcept;
    };
}
