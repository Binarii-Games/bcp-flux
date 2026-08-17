// The knock: an HS_INIT that carries data. A send to a peer whose identity this
// socket holds a certificate for goes as a knock, so application traffic rides
// from the first packet under an interim key while the ordinary handshake runs
// behind it and proves the address the only way it is ever proved, by the
// cookie echo in HS_RES.
//
// A knocked peer is a working session: it has a key, so flows open on it,
// number their packets, acknowledge and retransmit exactly as they always do.
// The only difference is a flag saying the address is not proven yet, which is
// what the caps in this file watch. When the handshake completes the interim
// key is replaced by the real one through the same slots a key rotation uses,
// so nothing the flows were tracking is disturbed.
//
// The seal and the open live in crypto/packet_seal.cpp. This file is the glue
// that reaches peers, keys and the caps.
#include <flux/socket/socket.h>
#include <flux/wire/packet_builder.h>

#include <cstring>
#include <new>

namespace bcp::flux
{
    namespace
    {
        /** The key that hides the sender's own public key inside the opener.
            It comes from the sender's ephemeral against the receiver's
            certificate key, which is the one exchange a receiver can run
            before it knows who is knocking. Both the ephemeral and the salt
            are fresh per attempt, so the key is used for one sealing and the
            ciphertext differs every time. */
        void DeriveKnockStaticKey(common::crypto::SessionKey& out,
                                  const common::crypto::SharedSecret& ephShared,
                                  const uint8_t salt[internal::WIRE_HS_SALT_SIZE]) noexcept
        {
            uint8_t context[internal::WIRE_HS_SALT_SIZE
                            + sizeof(internal::KNOCK_STATIC_LABEL)];
            std::memcpy(context, salt, internal::WIRE_HS_SALT_SIZE);
            std::memcpy(context + internal::WIRE_HS_SALT_SIZE,
                        internal::KNOCK_STATIC_LABEL,
                        sizeof(internal::KNOCK_STATIC_LABEL));
            common::crypto::DeriveSessionKey(out, ephShared, context, sizeof(context));
        }
    }

    common::Error Socket::InitKnock(const Config& config)
    {
        const Config::Knock& cfg = config.knock;
        knockEnabled_ = cfg.enable;
        knockMaxUnproven_ = cfg.maxUnprovenPeers != 0
            ? cfg.maxUnprovenPeers : internal::KNOCK_MAX_UNPROVEN_DEFAULT;
        knockUnprovenPacketLimit_ = cfg.unprovenPacketLimit != 0
            ? cfg.unprovenPacketLimit : internal::KNOCK_UNPROVEN_PACKET_LIMIT_DEFAULT;
        knockBudgetPerTick_ = cfg.budgetPerTick != 0
            ? cfg.budgetPerTick : internal::KNOCK_BUDGET_PER_TICK_DEFAULT;
        knockTtlWindowSeconds_ = cfg.ttlWindowSeconds != 0
            ? cfg.ttlWindowSeconds : internal::KNOCK_TTL_WINDOW_SECONDS_DEFAULT;
        knockBudgetThisTick_ = knockBudgetPerTick_;
        return common::Error::Ok;
    }

    void Socket::CombineKnockKey(common::crypto::SessionKey& outKey,
                                 common::crypto::SessionKey& outHeaderKey,
                                 const common::crypto::SharedSecret& staticShared,
                                 const common::crypto::SharedSecret& ephShared,
                                 const uint8_t salt[internal::WIRE_HS_SALT_SIZE]) noexcept
    {
        // One KDF pass. The static-static secret keys the hash, so only the two
        // identity holders reach it. The ephemeral secret and the salt make up
        // the context, so every attempt derives a distinct key.
        uint8_t context[common::crypto::SHARED_SIZE + internal::WIRE_HS_SALT_SIZE
                        + sizeof(internal::KNOCK_KEY_LABEL)];
        size_t n = 0;
        std::memcpy(context + n, ephShared.data(), ephShared.size());
        n += ephShared.size();
        std::memcpy(context + n, salt, internal::WIRE_HS_SALT_SIZE);
        n += internal::WIRE_HS_SALT_SIZE;
        std::memcpy(context + n, internal::KNOCK_KEY_LABEL, sizeof(internal::KNOCK_KEY_LABEL));
        n += sizeof(internal::KNOCK_KEY_LABEL);
        common::crypto::DeriveSessionKey(outKey, staticShared, context, n);
        common::crypto::DeriveSubKey(outHeaderKey.data(), outKey.data(),
                                     internal::HEADER_KEY_LABEL);
        common::crypto::Wipe(context, sizeof(context));
    }

    bool Socket::ArmKnock(Peer& peer, const common::crypto::PublicKey& certKey)
    {
        if (!knockEnabled_) return false;

        common::crypto::SecretKey ephSk;
        common::crypto::PublicKey ephPk;
        uint8_t salt[internal::WIRE_HS_SALT_SIZE];
        if (!common::crypto::GenerateKeypair(ephSk, ephPk)
            || !common::crypto::RandomBytes(salt, sizeof(salt)))
        {
            common::crypto::Wipe(ephSk.data(), ephSk.size());
            return false;
        }

        IdentityTable::Entry mine;
        (void)identities_.Find(IdentityTable::CURRENT, mine);

        common::crypto::SharedSecret staticShared;
        common::crypto::SharedSecret ephShared;
        common::crypto::ComputeSharedSecret(staticShared, mine.secretKey, certKey);
        common::crypto::ComputeSharedSecret(ephShared, ephSk, certKey);
        CombineKnockKey(peer.knockKey, peer.knockHeaderKey, staticShared, ephShared, salt);

        // The receiver needs this socket's public key to run the static
        // exchange, so it travels, but it travels sealed: in the clear it
        // would name the sender to anyone on the path and undo the
        // unlinkability the rotating tags and the masked counter provide.
        // It is not a claim either way. A sender that does not hold the
        // matching secret derives a different interim key and its packet
        // never opens.
        common::crypto::SessionKey staticSealKey;
        DeriveKnockStaticKey(staticSealKey, ephShared, salt);
        // One sealing under a key that exists for it alone, so the nonce
        // carries no information and a fixed one is safe.
        const common::crypto::Nonce sealNonce{};
        common::crypto::Tag sealTag;
        common::crypto::Encrypt(peer.knockIdentity, sealTag, staticSealKey, sealNonce,
                                mine.publicKey.data(), mine.publicKey.size());
        std::memcpy(peer.knockIdentity + common::crypto::KEY_SIZE,
                    sealTag.data(), sealTag.size());
        common::crypto::Wipe(staticSealKey.data(), staticSealKey.size());

        // The ephemeral secret dies here. Its public half travels, and the
        // handshake behind the knock brings a second one, so the session that
        // replaces this key is unrecoverable once both are gone.
        common::crypto::Wipe(ephSk.data(), ephSk.size());
        common::crypto::Wipe(staticShared.data(), staticShared.size());
        common::crypto::Wipe(ephShared.data(), ephShared.size());

        peer.knockActive = true;
        peer.knockFramed = true;   // until the far side answers, or the handshake lands
        peer.knockEphPk  = ephPk;
        std::memcpy(peer.knockSalt, salt, sizeof(salt));
        // Which of the receiver's keys this was encrypted toward, so it can
        // pick that one rather than attempting an agreement against each key
        // it holds. Computed from the certificate, which is all the sender has
        // and all it needs.
        peer.knockKeyId = IdentityTable::KeyIdOf(certKey);

        // A working session under the interim key: flows admit, packets number
        // and acknowledge, and the peer's replies open. The handshake is still
        // owed, and the retry pass finds this peer because the handshake state
        // below is left where it was, so IsValid stays false until it lands.
        peer.theirPk    = certKey;
        peer.nonceLane       = NonceLaneBetween(mine.publicKey, certKey);
        peer.session    = peer.knockKey;
        peer.headerKey  = peer.knockHeaderKey;
        common::crypto::DeriveSubKey(peer.macKey.data(), peer.session.data(),
                                     internal::MAC_KEY_LABEL);
        peer.sendCounter = 0;
        // The handshake state is left exactly where it was. This side is still
        // waiting for a challenge to answer, and pretending otherwise would
        // make it refuse the one that arrives. CanCarryTraffic is what says the
        // interim key is usable meanwhile.
        peer.confirmed   = false;
        if (peer.congestionBudget < minCongestionBudget_)
            peer.congestionBudget = minCongestionBudget_;
        return true;
    }

    void Socket::SendKnockOpener(const Address& addr)
    {
        // A knock with nothing to deliver: the opener and the interim key, in
        // the one packet the design allows. The builder runs the ordinary send
        // path, which seals it as a knock because the window is armed.
        (void)BuildPacket().NoFlow().Send(addr);
    }

    void Socket::MarkAddressProven(Peer& peer) noexcept
    {
        if (!peer.awaitingAddressProof) return;
        peer.awaitingAddressProof = false;
        peer.unprovenPacketsSeen  = 0;
        unprovenPeers_.fetch_sub(1, std::memory_order_relaxed);
    }

    void Socket::Handshake_Knock(PacketSlotHandle pHandle)
    {
        PacketSlot* packet = pHandle.Write();
        if (!packet) return;
        if (packet->dataSize < internal::KNOCK_HEADER_SIZE + internal::WIRE_TAG_SIZE) return;
        const Address from = packet->address;

        const uint8_t* saltField = packet->data + internal::KNOCK_OFF_SALT;
        const uint8_t* idRegion  = packet->data + internal::KNOCK_OFF_IDENTITY;
        common::crypto::PublicKey ephPk;
        std::memcpy(ephPk.data(), packet->data + internal::KNOCK_OFF_EPH, ephPk.size());

        uint32_t keyId = 0;
        for (size_t i = 0; i < internal::WIRE_KEY_ID_SIZE; ++i)
            keyId |= static_cast<uint32_t>(packet->data[internal::KNOCK_OFF_KEYID + i]) << (8 * i);

        // The claimed age, against this socket's own clock. A replayed opener
        // carries the stamp of the original, so it ages out of the window even
        // when the ring that would have refused it outright has been wiped by a
        // restart.
        uint64_t claimed = 0;
        for (size_t i = 0; i < 8; ++i)
            claimed |= static_cast<uint64_t>(packet->data[internal::KNOCK_OFF_CLOCK + i]) << (8 * i);
        const uint64_t nowWall = common::WallClockSeconds();
        const uint64_t skew = claimed > nowWall ? claimed - nowWall : nowWall - claimed;
        const bool fresh = skew <= knockTtlWindowSeconds_;

        // A peer already knocking opens with the key on its slot: the rest of
        // the window's packets cost a lookup rather than a key agreement, and
        // nothing can be re-created underneath them.
        {
            PeerHandle peerHandle = peers_.GetPeer(from);
            if (!peerHandle.Failed())
            {
                Peer* peer = peerHandle.Write();
                if (!peer) return;

                // While the window is open the interim key is on the peer.
                // After this side commits its handshake the sender may keep
                // knock-framing for up to a round trip, and the commit put
                // that key in the previous-key slot for exactly this.
                if (!fresh) return;   // a replay of one of its own packets
                const bool useCurrent = peer->knockActive;
                const bool usePrev    = !useCurrent && !peer->rotationConfirmed;
                if (!useCurrent && !usePrev) return;   // nothing left to open it with

                if (peer->awaitingAddressProof
                    && peer->unprovenPacketsSeen >= knockUnprovenPacketLimit_)
                    return;   // ejected unbuffered until the echo lands

                uint64_t counter = 0;
                const common::crypto::SessionKey& openKey =
                    useCurrent ? peer->knockKey : peer->prevSession;
                const common::crypto::SessionKey& openMask =
                    useCurrent ? peer->knockHeaderKey : peer->prevHeaderKey;
                // A mac-only opener is verified under the mac key of the same
                // generation, which is derived from the key above and so proves
                // the same thing the AEAD tag would.
                const common::crypto::SessionKey& openMacKey =
                    useCurrent ? peer->macKey : peer->prevMacKey;
                // The previous slot holds the interim key, and that key was
                // agreed against whichever key the opener named, so it carries
                // its own lane. Opening it with the committed one produces a
                // different nonce and it never opens.
                const uint8_t openNonceLane =
                    useCurrent ? peer->TheirNonceLane() : peer->TheirPrevNonceLane();
                if (!OpenKnockPacket(*packet, openKey, openMask, openMacKey,
                                     openNonceLane, counter))
                    return;
                if (!ReplayFor(peerHandle.GetSlotIndex()).Accept(counter))
                    return;
                if (peer->awaitingAddressProof) ++peer->unprovenPacketsSeen;
                const uint32_t nowStamp = SeenStamp(common::MonotonicMicros());
                if (static_cast<uint32_t>(nowStamp - peer->lastSeenAt) >= seenGrainStamp_)
                    peer->lastSeenAt = nowStamp;
            }
            else
            {
                // A new peer, so everything that costs work or memory is gated
                // before any of it is spent. Every gate below declines the same
                // way: with the ordinary challenge, so a sender whose opener
                // this socket will not take starts its handshake now instead of
                // waiting out a retry. The challenge is stateless and never
                // larger than the knock that provoked it, so answering costs
                // nothing an attacker can spend.
                if (!fresh) { Handshake_Challenge(from); return; }
                if (knockBudgetThisTick_ == 0) { Handshake_Challenge(from); return; }
                --knockBudgetThisTick_;

                // Which of this socket's keys the opener was aimed at. A
                // named key it no longer holds declines exactly as an opener
                // it cannot read does, so a sender working from a certificate
                // this socket has forgotten learns nothing from the shape of
                // the answer and simply falls back to the handshake.
                IdentityTable::Entry mine;
                const IdentityTable::Which which = identities_.Find(keyId, mine);
                if (which == IdentityTable::Which::None)
                {
                    Handshake_Challenge(from);
                    return;
                }

                // The sender's ephemeral against the named secret is the one
                // exchange available before the sender is known, and it
                // unseals the name. Its tag is also the cheap gate: a forgery
                // fails here, on one key agreement, rather than after the
                // second one.
                common::crypto::SharedSecret ephShared;
                common::crypto::ComputeSharedSecret(ephShared, mine.secretKey, ephPk);
                common::crypto::SessionKey staticSealKey;
                DeriveKnockStaticKey(staticSealKey, ephShared, saltField);
                const common::crypto::Nonce sealNonce{};
                common::crypto::Tag sealTag;
                std::memcpy(sealTag.data(), idRegion + common::crypto::KEY_SIZE,
                            sealTag.size());
                common::crypto::PublicKey theirStatic;
                const bool named = common::crypto::Decrypt(
                    theirStatic.data(), staticSealKey, sealNonce,
                    idRegion, theirStatic.size(), sealTag);
                common::crypto::Wipe(staticSealKey.data(), staticSealKey.size());
                if (!named)
                {
                    common::crypto::Wipe(ephShared.data(), ephShared.size());
                    // Aimed at a key this socket does not hold, or forged. A
                    // genuine sender is told to do it the ordinary way, and a
                    // forgery gets one stateless packet for its trouble.
                    Handshake_Challenge(from);
                    return;
                }

                common::crypto::SharedSecret staticShared;
                common::crypto::ComputeSharedSecret(staticShared, mine.secretKey, theirStatic);
                common::crypto::SessionKey knockKey;
                common::crypto::SessionKey knockHeaderKey;
                CombineKnockKey(knockKey, knockHeaderKey, staticShared, ephShared, saltField);
                common::crypto::SessionKey knockMacKey;
                common::crypto::DeriveSubKey(knockMacKey.data(), knockKey.data(),
                                             internal::MAC_KEY_LABEL);
                common::crypto::Wipe(staticShared.data(), staticShared.size());
                common::crypto::Wipe(ephShared.data(), ephShared.size());

                uint64_t counter = 0;
                const uint8_t theirNonceLane = NonceLaneBetween(theirStatic, mine.publicKey);
                const bool opened = OpenKnockPacket(*packet, knockKey, knockHeaderKey,
                                                    knockMacKey, theirNonceLane, counter);
                if (!opened)
                {
                    common::crypto::Wipe(knockKey.data(), knockKey.size());
                    common::crypto::Wipe(knockHeaderKey.data(), knockHeaderKey.size());
                    common::crypto::Wipe(knockMacKey.data(), knockMacKey.size());
                    Handshake_Challenge(from);
                    return;
                }
                // The open is the identity proof: only the holder of the secret
                // for this public key derives a key that opens here, so the id
                // is bound rather than claimed. It has to be bound now, because
                // the handshake behind this knock refuses a peer whose stored
                // id does not match the one it proves.
                const BcpId id = BcpId::Derive(theirStatic);

                // Unproven address, so the peer counts against the cap. Past
                // it, nothing is created and the plain handshake carries the
                // sender instead, which stays stateless until its echo.
                bool capped = false;
                if (unprovenPeers_.fetch_add(1, std::memory_order_relaxed) >= knockMaxUnproven_)
                {
                    unprovenPeers_.fetch_sub(1, std::memory_order_relaxed);
                    capped = true;
                }
                uint32_t slot = common::collections::SlotPool::INVALID;
                if (capped || peers_.RegisterPeer(from, &id, slot) != common::Error::Ok)
                {
                    if (!capped) unprovenPeers_.fetch_sub(1, std::memory_order_relaxed);
                    common::crypto::Wipe(knockKey.data(), knockKey.size());
                    common::crypto::Wipe(knockHeaderKey.data(), knockHeaderKey.size());
                    common::crypto::Wipe(knockMacKey.data(), knockMacKey.size());
                    Handshake_Challenge(from);
                    return;
                }
                SeedPeerRecvState(slot);

                {
                    PeerHandle fresh = peers_.GetPeer(from);
                    if (fresh.Failed()) return;
                    Peer* peer = fresh.Write();
                    if (!peer) return;
                    peer->theirPk        = theirStatic;
                    peer->nonceLane           = theirNonceLane == 0 ? 1 : 0;
                    peer->id             = id;
                    peer->hasId          = true;
                    peer->knockActive    = true;
                    peer->knockKey       = knockKey;
                    peer->knockHeaderKey = knockHeaderKey;
                    peer->session        = knockKey;
                    peer->headerKey      = knockHeaderKey;
                    common::crypto::DeriveSubKey(peer->macKey.data(), peer->session.data(),
                                                 internal::MAC_KEY_LABEL);
                    peer->sendCounter    = 0;
                    peer->state          = HandshakeState::ESTABLISHED;
                    // Deliberately not confirmed: that flag means a packet
                    // opened under a handshake-derived key, and it is what
                    // stops an HS_RES re-keying a proven session. The handshake
                    // behind this knock still has to run, so it must not be set
                    // by a knock.
                    peer->confirmed            = false;
                    peer->awaitingAddressProof = true;
                    peer->unprovenPacketsSeen  = 1;
                    peer->knockStartedAtMicros = common::MonotonicMicros();
                    if (peer->congestionBudget < minCongestionBudget_)
                        peer->congestionBudget = minCongestionBudget_;
                    ReplayFor(slot).Reset();
                    (void)ReplayFor(slot).Accept(counter);
                    RecordPeerEvent(*peer, slot, SocketEvent::PEER_KNOCKED);
                    // Opened on a key this socket has replaced, so the sender
                    // is working from a certificate that has not caught up.
                    // Its data still arrives, which is what keeping the key
                    // bought, but its handshake will be answered with the
                    // current key and refused until it holds a fresh one.
                    if (which == IdentityTable::Which::Previous)
                        RecordPeerEvent(*peer, slot, SocketEvent::PEER_STALE_IDENTITY);
                }
                common::crypto::Wipe(knockKey.data(), knockKey.size());
                common::crypto::Wipe(knockHeaderKey.data(), knockHeaderKey.size());
                common::crypto::Wipe(knockMacKey.data(), knockMacKey.size());

                // The handshake starts here, from the packet that carried the
                // data: the challenge is stateless, and the sender's echo of
                // its cookie is what proves the address and derives the real
                // session. One reply to one packet, so this cannot amplify.
                Handshake_Challenge(from);
            }
        }

        // Opened and accepted: hand it on exactly as an ordinary secure packet
        // is handed on, so nothing downstream learns knocks exist. An opener
        // carrying no payload has nothing to route.
        const PacketSlot* opened = pHandle.Read();
        if (!opened || opened->dataSize <= internal::WIRE_SECURE_HEAD_SIZE
                                           + internal::WIRE_TAG_SIZE)
            return;
        if (opened->SecureChannel() != internal::SECURE_CHANNEL_APP)
            ProcessSecureControl(std::move(pHandle));
        else if (opened->HasFlow())
            (void)ProcessFlowIn(std::move(pHandle));
        else
            (void)QueueReady(pHandle);
    }
}
