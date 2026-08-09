#pragma once

#include <cstdint>

#include <common/error.h>

#include <flux/address.h>
#include <flux/internal/constants.h>

// A transfer moves one length-announced run of bytes between buffers the
// application owns. Nothing is copied: the sender reads retransmits back out
// of the source buffer, and the receiver writes each packet straight to its
// offset in the destination. An outstanding packet costs its in-flight ring
// entry alone, so the window can be deep enough that the congestion
// controller, rather than a flow windoxw, is what bounds a fast long path.
//
// It runs beside flows rather than inside them. A transfer has its own secure
// channels, its own header, its own ids and its own poll call, and carries no
// flow header, no mode bits and no message framing. Nothing on the flow path
// changes to accommodate one, and the two mechanisms share only the peer's
// congestion state, which they must: one link, one budget, one pacing clock.
//
// The two types here are the whole application-facing surface. A
// TransferRequest is the receiver's decision point, handed over when a peer
// announces. A TransferView is what a finished transfer looks like coming out
// of PollTransfers, at either end.

namespace bcp::flux
{
    class Socket;

    /** A peer's announcement, and the answer to it.

        Obtained from Socket::PendingTransfer for the flow and peer a
        TRANSFER_INCOMING event named. Every request must be answered. Allow
        takes the buffer the bytes are written into and accepts Length() by
        doing so, and Reject tells the peer no. A request answered with
        neither holds the association until the flow stall timeout, which the
        peer sees as a stalled transfer rather than a refusal.

        A key, not a lease, in the manner of FlowHandle: it holds no lock and
        keeps nothing alive. Answering a request whose peer has gone reports
        NotFound rather than reaching a later occupant of the slot. */
    class TransferRequest
    {
    private:
        Socket*  socket_{nullptr};
        Address  peer_{};
        uint64_t length_{0};
        uint16_t flowId_{internal::INVALID_FLOW_ID};

    public:
        TransferRequest() = default;
        TransferRequest(Socket* socket, const Address& peer,
                        uint64_t length, uint16_t flowId) noexcept
            : socket_(socket), peer_(peer), length_(length), flowId_(flowId) {}

        /** Whether an announcement is actually waiting. False when the flow
            and peer name nothing pending, which is what a handler sees if the
            transfer was withdrawn between the event and the ask. */
        [[nodiscard]] bool Valid() const noexcept
        {
            return socket_ != nullptr && flowId_ != internal::INVALID_FLOW_ID;
        }

        /** Bytes the peer says it will send. The destination buffer has to be
            at least this large, and Allow accepts that by being called. */
        [[nodiscard]] uint64_t Length() const noexcept { return length_; }

        [[nodiscard]] uint16_t Flow() const noexcept { return flowId_; }
        [[nodiscard]] const Address& Peer() const noexcept { return peer_; }

        /** Accepts the transfer into `buffer`, which must hold Length() bytes
            and must not be read or moved until the transfer completes.

            Writes land at their own offsets from this moment, so the buffer is
            not filled front to back and only TransferProgress says how much of
            it is meaningful. Every write is bounded to Length() whatever the
            peer sends, because the receiver refuses a stride it did not expect
            and a sequence outside the count that length implies.

            @return InvalidState if the request is not valid, NotFound if the
                    association went away, InvalidParam for a null buffer. */
        [[nodiscard]] common::Error Allow(void* buffer) noexcept;

        /** Declines the transfer. The peer is told, so its send completes as
            Refused rather than stalling, and anything already held for this
            transfer is dropped. */
        common::Error Reject() noexcept;
    };

    /** A finished transfer, as PollTransfers reports it.

        Incoming, the bytes are the destination buffer now whole, and the
        transfer stays held until CompleteTransfer so the application can take
        its time. Outgoing, the bytes are null and the source buffer is free
        again, with Outcome saying whether the peer took it. Which direction
        this is reads off Bytes being null. */
    class TransferView
    {
    private:
        const void*   bytes_{nullptr};
        uint64_t      length_{0};
        Address       peer_{};
        uint16_t      flowId_{internal::INVALID_FLOW_ID};
        common::Error outcome_{common::Error::Ok};

    public:
        TransferView() = default;
        TransferView(const void* bytes, uint64_t length, const Address& peer,
                     uint16_t flowId, common::Error outcome) noexcept
            : bytes_(bytes), length_(length), peer_(peer),
              flowId_(flowId), outcome_(outcome) {}

        /** The buffer the application supplied. Null on a refused send, where
            no bytes were ever placed. */
        [[nodiscard]] const void* Bytes() const noexcept { return bytes_; }
        [[nodiscard]] uint64_t Length() const noexcept { return length_; }

        [[nodiscard]] uint16_t Flow() const noexcept { return flowId_; }
        [[nodiscard]] const Address& Peer() const noexcept { return peer_; }

        /** Ok when the run arrived whole, Refused when the far side declined
            it, and a path error when it stopped answering.

            Reported through a poll call rather than the event hook because
            this is a lifetime handoff and not a notification: until the sender
            sees it, the source buffer is still being read for retransmits. An
            application that never drains these finds out at once, since the id
            will not accept a second transfer until the first is answered. */
        [[nodiscard]] common::Error Outcome() const noexcept { return outcome_; }
    };
}
