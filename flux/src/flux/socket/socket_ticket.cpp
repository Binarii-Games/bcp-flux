// Resume notes: how a peer that restarts gets its session back without
// waiting, and without the receiver remembering anything.
//
// Once a session proves itself, each side seals a note for its peer. The note
// is sealed for the ISSUER's own future self, so the holder stores bytes it
// cannot read and the issuer stores nothing at all. When the holder comes back
// it sends the note inside its opener. The opener already proves the sender
// holds the key it presents, the note proves that key held a session here, and
// together that is everything the handshake would have established, so the peer
// is installed already confirmed. That is the whole point: not a shortened
// handshake, none of it.
//
// Nothing secret is in a note, which is what makes handing the bytes to an
// application safe. A thief holding one cannot present it, because presenting
// it means producing an opener that opens under the key the note names.
//
// This file is the note itself and the issuing half of the contract. Spending
// one lives with the opener, in socket_knock.cpp.
#include <flux/socket/socket.h>
#include <flux/wire/packet_builder.h>

#include <cstring>
#include <utility>

namespace bcp::flux
{
    void Socket::InitResumeNotes(const Config& config) noexcept
    {
        keepResumeNotes_ = config.keepResumeNotes;
        ticketLifetime_  = config.resumeNoteSeconds != 0
            ? config.resumeNoteSeconds
            : internal::TICKET_LIFETIME_SECONDS_DEFAULT;

        // From the identity secret, so a restart re-derives the same key off
        // the same identity file and a note issued before it still opens. The
        // current keypair is the one used: rotating the identity retires every
        // outstanding note, which is the real ceiling on their lifetime and is
        // why the stated validity is measured in days rather than months.
        IdentityTable::Entry mine;
        (void)identities_.Find(IdentityTable::CURRENT, mine);
        common::crypto::DeriveSubKey(ticketSealKey_.data(), mine.secretKey.data(),
                                     internal::TICKET_SEAL_LABEL);
    }

    void Socket::SealResumeNote(uint8_t* out,
                                const common::crypto::PublicKey& holderKey,
                                const uint8_t holderTag[internal::WIRE_HS_TAG_SIZE]) noexcept
    {
        uint8_t body[internal::TICKET_SEALED_SIZE];
        std::memcpy(body, holderTag, internal::WIRE_HS_TAG_SIZE);
        const uint64_t issued = common::WallClockSeconds();
        for (size_t i = 0; i < 8; ++i)
            body[internal::WIRE_HS_TAG_SIZE + i] = static_cast<uint8_t>(issued >> (8 * i));

        // A fresh nonce per note, carried rather than derived: the issuer keeps
        // no counter to derive one from, and a counter that restarted with the
        // process would repeat a nonce under a key that did not change.
        common::crypto::Nonce nonce;
        if (!common::crypto::RandomBytes(nonce.data(), nonce.size()))
        {
            std::memset(out, 0, internal::TICKET_WIRE_SIZE);   // never opens
            return;
        }

        common::crypto::Tag tag;
        common::crypto::Encrypt(out + nonce.size(), tag, ticketSealKey_, nonce,
                                body, sizeof(body),
                                holderKey.data(), holderKey.size());
        std::memcpy(out, nonce.data(), nonce.size());
        std::memcpy(out + nonce.size() + sizeof(body), tag.data(), tag.size());
        common::crypto::Wipe(body, sizeof(body));
    }

    bool Socket::OpenResumeNote(const uint8_t* note,
                                const common::crypto::PublicKey& holderKey,
                                uint8_t outTag[internal::WIRE_HS_TAG_SIZE]) noexcept
    {
        common::crypto::Nonce nonce;
        common::crypto::Tag tag;
        std::memcpy(nonce.data(), note, nonce.size());
        std::memcpy(tag.data(), note + nonce.size() + internal::TICKET_SEALED_SIZE,
                    tag.size());

        // The holder's key is the associated data, so a note only opens against
        // the key its presenter proved. A note lifted from one peer and offered
        // by another fails here rather than anywhere later.
        uint8_t body[internal::TICKET_SEALED_SIZE];
        if (!common::crypto::Decrypt(body, ticketSealKey_, nonce,
                                     note + nonce.size(), sizeof(body), tag,
                                     holderKey.data(), holderKey.size()))
            return false;

        uint64_t issued = 0;
        for (size_t i = 0; i < 8; ++i)
            issued |= static_cast<uint64_t>(body[internal::WIRE_HS_TAG_SIZE + i]) << (8 * i);
        const uint64_t now = common::WallClockSeconds();

        // Age only, not a clock window in both directions: a note stamped in
        // the future is a clock that moved, not an attack, and refusing it
        // would strand a peer over something it cannot see or fix.
        const bool expired = now > issued && (now - issued) > ticketLifetime_;
        if (expired)
        {
            common::crypto::Wipe(body, sizeof(body));
            return false;
        }

        std::memcpy(outTag, body, internal::WIRE_HS_TAG_SIZE);
        common::crypto::Wipe(body, sizeof(body));
        return true;
    }

    void Socket::SendPendingTicket(const Address& to, PeerHandle peerHandle, uint64_t now)
    {
        PeerSendMaterials materials;
        uint8_t note[internal::TICKET_WIRE_SIZE];
        {
            // The transferred handle is this function's to release: the gather
            // happens in this scope and the send after it, so the peer lock is
            // never held across the syscall.
            PeerHandle owned = std::move(peerHandle);
            if (owned.Failed()) return;
            Peer* peer = owned.Write();
            if (!peer || !peer->IsValid() || !peer->ticketSendPending) return;

            // Only to a peer that has proven its session. A note is a durable
            // credential, and the announced tag it names is only known once the
            // handshake said so.
            if (!peer->confirmed) return;
            if (peer->ticketSentAtMicros != 0
                && now - peer->ticketSentAtMicros < internal::TICKET_RESEND_MICROS)
                return;
            peer->ticketSentAtMicros = now;

            SealResumeNote(note, peer->theirPk, peer->announcedTag);
            materials = GatherSendMaterials(*peer);
        }

        SendSecureControl(to, materials, internal::SECURE_CHANNEL_TICKET,
                          note, sizeof(note));
        common::crypto::Wipe(materials.key.data(), materials.key.size());
    }

    void Socket::Ticket_Update(const Address& from, const uint8_t* payload, size_t len)
    {
        if (len < internal::WIRE_TICKET_PAYLOAD_SIZE) return;

        // Acknowledged whatever happens to it, so a holder that was told not to
        // keep notes does not leave its issuer resending one forever.
        PeerSendMaterials materials;
        {
            PeerHandle peerHandle = peers_.GetPeer(from);
            if (peerHandle.Failed()) return;
            Peer* peer = peerHandle.Write();
            if (!peer || !peer->IsValid()) return;

            if (keepResumeNotes_)
            {
                std::memcpy(peer->resumeNote, payload, internal::TICKET_WIRE_SIZE);
                peer->hasResumeNote = true;
                RecordPeerEvent(*peer, peerHandle.GetSlotIndex(),
                                SocketEvent::RESUME_NOTE_RECEIVED);
            }
            materials = GatherSendMaterials(*peer);
        }

        SendSecureControl(from, materials, internal::SECURE_CHANNEL_TICKET_ACK,
                          nullptr, 0);
        common::crypto::Wipe(materials.key.data(), materials.key.size());
    }

    void Socket::Ticket_Acked(const Address& from, const uint8_t* payload, size_t len)
    {
        (void)payload;
        (void)len;
        PeerHandle peerHandle = peers_.GetPeer(from);
        if (peerHandle.Failed()) return;
        Peer* peer = peerHandle.Write();
        if (!peer) return;
        peer->ticketSendPending = false;
    }
}
