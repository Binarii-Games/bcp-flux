// The ticket half of the socket: issuing resumption notes to peers, keeping
// the notes peers issue us, and moving them through whichever persistence the
// application configured. The table itself lives in ticket/ticket_table.cpp;
// this file is the glue that reaches the socket's peers, sending machinery
// and configuration, the same split socket_transfer.cpp has with the
// transfer table.
#include <flux/socket/socket.h>

#include <cstring>

#include <common/wire/bytes_writer.h>
#include <common/wire/bytes_reader.h>

namespace bcp::flux
{
    // The labels that keep every ticket derivation in its own domain. The
    // seal key folds the issue epoch into its last two bytes, which is what
    // makes bumping the epoch a mass revocation: a different input, a
    // different key, and every blob sealed before the bump stops opening.
    static constexpr uint8_t TICKET_SECRET_LABEL[16] = {
        'f','l','u','x','-','t','k','t','-','s','e','c','r','e','t',0
    };
    static constexpr uint8_t TICKET_SEAL_LABEL[16] = {
        'f','l','u','x','-','t','k','t','-','s','e','a','l',0,0
    };

    common::Error Socket::InitTickets(const Config& config)
    {
        const Config::Tickets& cfg = config.tickets;

        if (cfg.directory != nullptr && cfg.onSave != nullptr)
            return common::Error::InvalidParam;

        ticketSaveHook_    = cfg.onSave;
        ticketSaveContext_ = cfg.context;
        ticketLifetime_    = cfg.lifetimeSeconds != 0
            ? cfg.lifetimeSeconds
            : internal::TICKET_LIFETIME_SECONDS_DEFAULT;

        // The seal key exists whether or not anything is stored, because
        // issuing is unconditional. Derived, never stored: the identity
        // secret and the epoch reproduce it every run, which is exactly why
        // a persistent identity means notes survive this socket's restarts.
        uint8_t label[16];
        std::memcpy(label, TICKET_SEAL_LABEL, sizeof(label));
        label[14] = static_cast<uint8_t>(cfg.sealEpoch >> 0);
        label[15] = static_cast<uint8_t>(cfg.sealEpoch >> 8);
        common::crypto::DeriveSubKey(ticketSealKey_.data(), secretKey_.data(), label);

        uint64_t seed = 0;
        if (!common::crypto::RandomBytes(reinterpret_cast<uint8_t*>(&seed), sizeof(seed)))
            return common::Error::NotInitialized;
        nextNoteId_.store(seed | 1, std::memory_order_relaxed);   // never zero

        if (cfg.poolCount == 0)
            return common::Error::Ok;   // notes received will be dropped

        const common::Error table = tickets_.Init(cfg.poolCount);
        if (table != common::Error::Ok) return table;

        if (cfg.directory != nullptr)
        {
            const common::Error store = ticketStore_.Init(cfg.directory);
            if (store != common::Error::Ok) return store;

            // Load what a previous run left behind, purging what no longer
            // deserves the disk: bad encodings and expired notes. Contents
            // are not judged past that, because the unseal at resume is the
            // only judge that counts.
            struct LoadContext { Socket* self; uint64_t now; };
            LoadContext context{ this, common::WallClockSeconds() };
            ticketStore_.LoadAll(&context,
                [](void* raw, const uint8_t* bundle, size_t len) -> bool
                {
                    LoadContext* load = static_cast<LoadContext*>(raw);
                    TicketTable::Entry entry;
                    if (!TicketTable::DecodeBundle(bundle, len, entry)) return false;
                    if (entry.expiryWall <= load->now) return false;
                    return load->self->tickets_.Store(entry, load->now)
                           == common::Error::Ok;
                });
        }
        return common::Error::Ok;
    }

    common::Error Socket::ImportTicket(const uint8_t* bundle, size_t len)
    {
        if (!initialized_.load(std::memory_order_acquire))
            return common::Error::NotInitialized;
        if (!tickets_.Enabled()) return common::Error::NotInitialized;

        TicketTable::Entry entry;
        if (!TicketTable::DecodeBundle(bundle, len, entry))
            return common::Error::InvalidParam;
        return tickets_.Store(entry, common::WallClockSeconds());
    }

    void Socket::PersistTicket(const TicketTable::Entry& entry)
    {
        if (ticketSaveHook_ == nullptr && !ticketStore_.Active()) return;

        uint8_t bundle[TicketTable::BUNDLE_MAX];
        const size_t len = TicketTable::EncodeBundle(entry, bundle, sizeof(bundle));
        if (len == 0) return;

        if (ticketSaveHook_ != nullptr)
            ticketSaveHook_(ticketSaveContext_, entry.issuerId.id.data(), bundle, len);
        else
            ticketStore_.Save(entry.issuerId.id.data(), bundle, len);
        common::crypto::Wipe(bundle, sizeof(bundle));
    }

    void Socket::SendPendingTicket(const Address& to, PeerHandle peerHandle, uint64_t now)
    {
        PeerSendMaterials materials;
        uint64_t noteId = 0;
        common::crypto::SessionKey ticketSecret;
        common::crypto::PublicKey  holderPk;
        {
            // Transferred handle, grant-style: gather under the lock, seal
            // and send after it.
            PeerHandle owned = std::move(peerHandle);
            if (owned.Failed()) return;
            Peer* peer = owned.Write();
            if (!peer || !peer->IsValid() || !peer->ticketSendPending) return;

            // Not before the peer has opened something under the session key.
            // Until then the identity bound to the slot is only what a
            // handshake message claimed, and a note is a durable credential,
            // so it waits for the proof. This also keeps the wire quiet while
            // the other side may still be mid-handshake, where its retry
            // budget is finite and every extra packet on a damaged link is a
            // schedule the recovery did not choose.
            if (!peer->confirmed) return;

            if (peer->ticketSentAtMicros != 0
                && now - peer->ticketSentAtMicros < internal::TICKET_RESEND_MICROS)
                return;
            peer->ticketSentAtMicros = now;

            // The id is drawn once per session, at the first send, so every
            // resend repeats the same note and a stale ack cannot clear a
            // newer one.
            if (peer->issuedNoteId == 0)
                peer->issuedNoteId = nextNoteId_.fetch_add(1, std::memory_order_relaxed);
            noteId   = peer->issuedNoteId;
            holderPk = peer->theirPk;
            common::crypto::DeriveSubKey(ticketSecret.data(), peer->resumeRoot.data(),
                                         TICKET_SECRET_LABEL);
            materials = GatherSendMaterials(*peer);
        }

        // The sealed body, built and encrypted in place into the blob.
        uint8_t plain[internal::TICKET_SEALED_SIZE];
        uint16_t plainWritten = 0;
        common::BytesWriter body{plain, &plainWritten, sizeof(plain)};
        bool ok = body.PutBytes(holderPk.data(), holderPk.size());
        ok = ok && body.PutBytes(ticketSecret.data(), ticketSecret.size());
        ok = ok && body.PutU64(common::WallClockSeconds());
        ok = ok && body.PutU64(noteId);
        ok = ok && body.PutU32(ticketLifetime_);

        uint8_t blob[internal::TICKET_BLOB_SIZE];
        common::crypto::Nonce nonce;
        ok = ok && common::crypto::RandomBytes(nonce.data(), nonce.size());
        if (ok)
        {
            common::crypto::Tag tag;
            common::crypto::Encrypt(blob + nonce.size(), tag, ticketSealKey_, nonce,
                                    plain, sizeof(plain));
            std::memcpy(blob, nonce.data(), nonce.size());
            std::memcpy(blob + nonce.size() + sizeof(plain), tag.data(), tag.size());

            uint8_t payload[internal::WIRE_TICKET_PAYLOAD_SIZE];
            uint16_t payloadWritten = 0;
            common::BytesWriter op{payload, &payloadWritten, sizeof(payload)};
            ok = op.PutU64(noteId);
            ok = ok && op.PutU32(ticketLifetime_);
            ok = ok && op.PutU16(static_cast<uint16_t>(sizeof(blob)));
            ok = ok && op.PutBytes(blob, sizeof(blob));
            if (ok)
                SendSecureControl(to, materials, internal::SECURE_CHANNEL_TICKET,
                                  payload, payloadWritten);
        }

        common::crypto::Wipe(plain, sizeof(plain));
        common::crypto::Wipe(ticketSecret.data(), ticketSecret.size());
        common::crypto::Wipe(materials.key.data(), materials.key.size());
    }

    void Socket::Ticket_Update(const Address& from, const uint8_t* payload, size_t len)
    {
        common::BytesReader reader{payload, len};
        uint64_t noteId   = 0;
        uint32_t lifetime = 0;
        uint16_t blobLen  = 0;
        if (!reader.TakeU64(noteId) || !reader.TakeU32(lifetime)
            || !reader.TakeU16(blobLen))
            return;
        if (blobLen == 0 || blobLen > internal::TICKET_BLOB_SIZE || blobLen > reader.r)
            return;
        const uint8_t* blob = reader.p;

        // Everything the entry needs, gathered in one locked visit. The ack
        // goes out whether or not the note is kept: the issuer's question is
        // "did it arrive", and turning a full pool into an endless resend
        // answers nothing.
        TicketTable::Entry entry{};
        PeerSendMaterials materials;
        uint32_t peerSlot = 0;
        {
            PeerHandle peerHandle = peers_.GetPeer(from);
            if (peerHandle.Failed()) return;
            Peer* peer = peerHandle.Write();
            if (!peer || !peer->IsValid() || !peer->hasId) return;

            entry.live       = true;
            entry.issuerId   = peer->id;
            entry.issuerPk   = peer->theirPk;
            entry.addrHint   = from;
            entry.noteId     = noteId;
            entry.expiryWall = common::WallClockSeconds() + lifetime;
            entry.blobLen    = blobLen;
            std::memcpy(entry.blob, blob, blobLen);
            common::crypto::DeriveSubKey(entry.secret.data(), peer->resumeRoot.data(),
                                         TICKET_SECRET_LABEL);
            peerSlot  = peerHandle.GetSlotIndex();
            materials = GatherSendMaterials(*peer);
        }

        const bool stored = tickets_.Enabled()
            && tickets_.Store(entry, common::WallClockSeconds()) == common::Error::Ok;
        if (stored)
        {
            PersistTicket(entry);
            PeerHandle peerHandle = peers_.GetPeer(from);
            if (!peerHandle.Failed())
            {
                Peer* peer = peerHandle.Write();
                if (peer && peer->IsValid())
                    RecordPeerEvent(*peer, peerSlot, SocketEvent::TICKET_RECEIVED);
            }
        }
        common::crypto::Wipe(entry.secret.data(), entry.secret.size());

        uint8_t ack[internal::WIRE_TICKET_ACK_PAYLOAD_SIZE];
        uint16_t ackWritten = 0;
        common::BytesWriter op{ack, &ackWritten, sizeof(ack)};
        if (op.PutU64(noteId))
            SendSecureControl(from, materials, internal::SECURE_CHANNEL_TICKET_ACK,
                              ack, ackWritten);
        common::crypto::Wipe(materials.key.data(), materials.key.size());
    }

    void Socket::Ticket_Acked(const Address& from, const uint8_t* payload, size_t len)
    {
        common::BytesReader reader{payload, len};
        uint64_t noteId = 0;
        if (!reader.TakeU64(noteId) || noteId == 0) return;

        PeerHandle peerHandle = peers_.GetPeer(from);
        if (peerHandle.Failed()) return;
        Peer* peer = peerHandle.Write();
        if (!peer || !peer->IsValid()) return;
        if (peer->ticketSendPending && peer->issuedNoteId == noteId)
            peer->ticketSendPending = false;
    }
}
