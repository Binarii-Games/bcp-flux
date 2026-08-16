#include <flux/crypto/packet_seal.h>

#include <cstring>

#include <common/platform.h>             // WallClockSeconds, for the knock TTL stamp
#include <flux/internal/constants.h>
#include <flux/socket/socket.h>          // Controls and SocketOpCode

namespace bcp::flux
{
    namespace
    {
        /** Rebuilds the XChaCha20 nonce locally; the wire carries only the 8-byte
            counter. The lane byte splits the nonce space between the two sides'
            independent counters, which share one key. */
        void ExpandNonce(common::crypto::Nonce& out, uint64_t counter, uint8_t lane) noexcept
        {
            out = {};
            for (size_t i = 0; i < internal::WIRE_NONCE_SIZE; ++i)
                out[i] = static_cast<uint8_t>(counter >> (8 * i));
            out[internal::WIRE_NONCE_SIZE] = lane;
        }
        /** Writes the little-endian 8-byte counter into a packet's nonce field. */
        void StampNonceCounter(uint8_t* nonceField, uint64_t counter) noexcept
        {
            for (size_t i = 0; i < internal::WIRE_NONCE_SIZE; ++i)
                nonceField[i] = static_cast<uint8_t>(counter >> (8 * i));
        }
        /** The counter has to travel (the receiver cannot know which packet
            this is otherwise) but travelling in the clear makes it a serial
            number, and a sequence that stops at one address and resumes at the
            next value from another address links a peer across a migration no
            matter how the tag rotates. So the field carries the counter
            encrypted under a mask derived from the peer's header key and this
            packet's AEAD tag: the tag is unique and unpredictable per packet,
            so the same counter never produces the same bytes twice, and an
            observer sees eight bytes that never form a sequence.
            Key-holders both sides recompute it identically; nobody else can.

            Masking is its own inverse, so one function serves both directions.

            @pre `aeadTag` is the packet's final tag: on send that means after
                 the seal, on receive before the open. */
        void MaskNonceCounter(uint8_t* nonceField,
                              const common::crypto::SessionKey& headerKey,
                              const uint8_t* aeadTag) noexcept
        {
            uint8_t mask[common::crypto::KEY_SIZE];
            common::crypto::DeriveSubKey(mask, headerKey.data(), aeadTag);
            for (size_t i = 0; i < internal::WIRE_NONCE_SIZE; ++i)
                nonceField[i] ^= mask[i];
            common::crypto::Wipe(mask, sizeof(mask));
        }
        /** Reads the little-endian 8-byte counter out of a nonce field. */
        uint64_t ReadNonceCounter(const uint8_t* nonceField) noexcept
        {
            uint64_t counter = 0;
            for (size_t i = 0; i < internal::WIRE_NONCE_SIZE; ++i)
                counter |= static_cast<uint64_t>(nonceField[i]) << (8 * i);
            return counter;
        }
        /** Builds the AEAD associated data: the controller byte, plus the 4-byte
            migration tag on a tagged packet. Both are readable on the wire and
            neither is alterable.

            @param tag Null on an untagged packet.
            @return The AAD length. */
        size_t BuildSecureAad(uint8_t* aad, uint8_t controller, const uint8_t* tag) noexcept
        {
            aad[0] = controller;
            size_t aadLen = internal::WIRE_CONTROLLER_SIZE;
            if (tag)
            {
                std::memcpy(aad + aadLen, tag, internal::WIRE_PEER_TAG_SIZE);
                aadLen += internal::WIRE_PEER_TAG_SIZE;
            }
            return aadLen;
        }
    }

    namespace
    {
        /** Wraps an already-built payload in the knock opener. The payload was
            written at ordinary secure offsets; this lifts it into the knock
            interior with the sender's original controller byte leading, pads
            to the fixed packet size, and authenticates the whole cleartext
            header. The counter is masked exactly as a secure packet's is,
            under the knock header key.

            A payload too large for the knock interior seals nothing and
            zeroes the packet: an empty datagram the receiver drops. Reliable
            bodies recover, because their retransmit re-seals from staging
            under whatever framing the peer has by then, and MaxPayload told
            the caller the ceiling in the first place. */
        void SealKnockPacket(PacketSlot& dst, const uint8_t* plaintext,
                             size_t bodyLen,
                             const PeerSendMaterials& materials) noexcept
        {
            // Unreachable through the send path: PreProcessOut refuses an
            // oversized payload before the flow admits it, and the batch
            // ceiling follows the same bound. Kept as a last guard so a
            // future caller cannot walk off the end of the slot, and it
            // produces an empty packet the sender drops rather than a
            // truncated one the receiver would try to open.
            if (bodyLen > internal::KNOCK_PAYLOAD_MAX)
            {
                dst.dataSize = 0;
                return;
            }

            uint8_t inner[internal::KNOCK_INNER_SIZE] = {};
            // The original controller travels inside the seal so the open can
            // restore the packet's real shape. Untagged by construction: no
            // session means no migration tag, and the open lays content out
            // at untagged offsets.
            inner[0] = dst.data[0] & static_cast<uint8_t>(~ToByte(Controls::CTRL_TAGGED));
            inner[1] = static_cast<uint8_t>(bodyLen >> 0);
            inner[2] = static_cast<uint8_t>(bodyLen >> 8);
            std::memcpy(inner + internal::KNOCK_INNER_PREFIX, plaintext, bodyLen);

            uint8_t* header = dst.data;
            header[0] = ToByte(Controls::CTRL_INTERNAL | Controls::CTRL_UNSECURE);
            header[1] = static_cast<uint8_t>(SocketOpCode::HS_KNOCK);
            header[internal::KNOCK_OFF_VERSION]     = static_cast<uint8_t>(internal::VERSION >> 0);
            header[internal::KNOCK_OFF_VERSION + 1] = static_cast<uint8_t>(internal::VERSION >> 8);
            uint32_t caps = 0;   // capability bits ride zeroed until one exists
            for (size_t i = 0; i < internal::VERSION_CAPS_SIZE; ++i)
                header[internal::KNOCK_OFF_CAPS + i] = static_cast<uint8_t>(caps >> (8 * i));
            StampNonceCounter(header + internal::KNOCK_OFF_COUNTER, materials.counter);
            std::memcpy(header + internal::KNOCK_OFF_EPH, materials.knockEphPk.data(),
                        materials.knockEphPk.size());
            std::memcpy(header + internal::KNOCK_OFF_SALT, materials.knockSalt,
                        sizeof(materials.knockSalt));
            const uint64_t clock = common::WallClockSeconds();
            for (size_t i = 0; i < 8; ++i)
                header[internal::KNOCK_OFF_CLOCK + i] = static_cast<uint8_t>(clock >> (8 * i));
            for (size_t i = 0; i < internal::WIRE_KEY_ID_SIZE; ++i)
                header[internal::KNOCK_OFF_KEYID + i] =
                    static_cast<uint8_t>(materials.knockKeyId >> (8 * i));
            std::memcpy(header + internal::KNOCK_OFF_IDENTITY, materials.knockIdentity,
                        sizeof(materials.knockIdentity));

            common::crypto::Nonce nonce;
            ExpandNonce(nonce, materials.counter, materials.lane);

            common::crypto::Tag aeadTag;
            common::crypto::Encrypt(dst.data + internal::KNOCK_HEADER_SIZE, aeadTag,
                                    materials.key, nonce,
                                    inner, sizeof(inner),
                                    header, internal::KNOCK_HEADER_SIZE);
            std::memcpy(dst.data + internal::KNOCK_HEADER_SIZE + sizeof(inner),
                        aeadTag.data(), aeadTag.size());
            dst.dataSize = internal::MAX_WIRE_PACKET_SIZE;

            // Masked last, with the mask keyed by this packet's own tag, the
            // same discipline as a secure packet. The AAD covered the real
            // counter, so the open restores it before verifying.
            MaskNonceCounter(header + internal::KNOCK_OFF_COUNTER,
                             materials.headerKey, aeadTag.data());
            common::crypto::Wipe(inner, sizeof(inner));
        }
    }

    bool OpenKnockPacket(PacketSlot& packet,
                         const common::crypto::SessionKey& knockKey,
                         const common::crypto::SessionKey& knockHeaderKey,
                         uint8_t senderNonceLane,
                         uint64_t& outCounter) noexcept
    {
        if (packet.dataSize < internal::KNOCK_HEADER_SIZE + internal::WIRE_TAG_SIZE)
            return false;
        const size_t cipherLen =
            packet.dataSize - internal::KNOCK_HEADER_SIZE - internal::WIRE_TAG_SIZE;
        if (cipherLen < internal::KNOCK_INNER_PREFIX) return false;

        common::crypto::Tag tag;
        std::memcpy(tag.data(), packet.data + packet.dataSize - internal::WIRE_TAG_SIZE,
                    tag.size());

        // The AAD is the header as the sender authenticated it, counter
        // unmasked. Rebuilt in a copy so a failed open leaves the wire bytes
        // exactly as they arrived for the next attempt.
        uint8_t aad[internal::KNOCK_HEADER_SIZE];
        std::memcpy(aad, packet.data, sizeof(aad));
        MaskNonceCounter(aad + internal::KNOCK_OFF_COUNTER, knockHeaderKey, tag.data());
        const uint64_t counter = ReadNonceCounter(aad + internal::KNOCK_OFF_COUNTER);

        common::crypto::Nonce nonce;
        ExpandNonce(nonce, counter, senderNonceLane);

        if (!common::crypto::Decrypt(packet.data + internal::KNOCK_HEADER_SIZE,
                                     knockKey, nonce,
                                     packet.data + internal::KNOCK_HEADER_SIZE,
                                     cipherLen, tag,
                                     aad, sizeof(aad)))
            return false;

        // Verified and decrypted: rewrite in place into an already-opened
        // ordinary packet, marked as having ridden the first flight, so the
        // rest of the receive path never learns knocks exist.
        const uint8_t* inner = packet.data + internal::KNOCK_HEADER_SIZE;
        const uint8_t  originalController = inner[0];
        const uint16_t innerLen = static_cast<uint16_t>(inner[1])
                                | static_cast<uint16_t>(inner[2]) << 8;
        if (innerLen > cipherLen - internal::KNOCK_INNER_PREFIX) return false;

        packet.data[0] = originalController | internal::WIRE_CTRL_KNOCKED;
        StampNonceCounter(packet.data + internal::WIRE_CONTROLLER_SIZE, counter);
        std::memmove(packet.data + internal::WIRE_SECURE_HEAD_SIZE,
                     inner + internal::KNOCK_INNER_PREFIX, innerLen);
        packet.dataSize = static_cast<uint16_t>(
            internal::WIRE_SECURE_HEAD_SIZE + innerLen + internal::WIRE_TAG_SIZE);
        outCounter = counter;
        return true;
    }

    void SealSecurePacket(PacketSlot& dst, const uint8_t* plaintext,
                                   size_t headerSize, size_t bodyLen,
                                   const PeerSendMaterials& materials, bool tagged) noexcept
    {
        if (materials.knock)
        {
            SealKnockPacket(dst, plaintext, bodyLen, materials);
            return;
        }
        // On a tagged packet the migration tag goes into the authenticated
        // header (and the AAD). `dst.data[0]` (controller) is already set; for a
        // retransmit the caller has copied the header from staging, for in-place
        // `plaintext` points into `dst` itself.
        uint8_t aad[internal::WIRE_CONTROLLER_SIZE + internal::WIRE_PEER_TAG_SIZE];
        const uint8_t* tagBytes = nullptr;
        if (tagged)
        {
            uint8_t* tagField = dst.data + internal::WIRE_SECURE_HEAD_SIZE;
            std::memcpy(tagField, materials.tag.data(), materials.tag.size());
            tagBytes = materials.tag.data();
        }
        const size_t aadLen = BuildSecureAad(aad, dst.data[0], tagBytes);

        uint8_t* nonceField = dst.data + internal::WIRE_CONTROLLER_SIZE;
        StampNonceCounter(nonceField, materials.counter);

        common::crypto::Nonce nonce;
        ExpandNonce(nonce, materials.counter, materials.lane);

        common::crypto::Tag aeadTag;
        common::crypto::Encrypt(dst.data + headerSize, aeadTag, materials.key, nonce,
                                plaintext, bodyLen, aad, aadLen);

        // After the ciphertext, not before it. The caller sized dataSize to
        // header plus body, so the tag extends the packet rather than sitting
        // in space someone reserved for it.
        std::memcpy(dst.data + headerSize + bodyLen, aeadTag.data(), aeadTag.size());
        dst.dataSize = static_cast<uint16_t>(headerSize + bodyLen + internal::WIRE_TAG_SIZE);

        // Last, because the mask comes from the tag the seal just produced. The
        // nonce was built from the real counter above; only the wire copy is
        // masked, so the AEAD is unaffected.
        MaskNonceCounter(nonceField, materials.headerKey, aeadTag.data());
    }

    void SealMacOnlyPacket(PacketSlot& dst, size_t headerSize, size_t bodyLen,
                                   const PeerSendMaterials& materials, bool tagged) noexcept
    {
        // The knock window has no readable-on-the-wire tier: everything rides
        // the full opener seal, and the mac-only choice resumes with the
        // session. Costs the sender some crypto for a round trip, loses
        // nothing else.
        if (materials.knock)
        {
            SealKnockPacket(dst, dst.data + headerSize, bodyLen, materials);
            return;
        }
        if (tagged)
        {
            uint8_t* tagField = dst.data + internal::WIRE_SECURE_HEAD_SIZE;
            std::memcpy(tagField, materials.tag.data(), materials.tag.size());
        }

        uint8_t* nonceField = dst.data + internal::WIRE_CONTROLLER_SIZE;
        StampNonceCounter(nonceField, materials.counter);

        // One pass over everything that is about to travel, the controller byte
        // included. Nothing is encrypted, so there is no ciphertext to separate
        // from associated data, and no scratch to assemble.
        const size_t covered = headerSize + bodyLen;
        common::crypto::Mac mac;
        common::crypto::ComputeMac(mac, materials.macKey, dst.data, covered);
        std::memcpy(dst.data + covered, mac.data(), mac.size());
        dst.dataSize = static_cast<uint16_t>(covered + internal::WIRE_TAG_SIZE);

        // Last, so the MAC covered the real counter. The receiver reads the MAC
        // off the end before it has verified anything, unmasks with it, and only
        // then checks: a tampered counter or a tampered MAC both end in a
        // mismatch.
        MaskNonceCounter(nonceField, materials.headerKey, mac.data());
    }

    bool OpenMacOnlyPacket(PacketSlot& packet,
                                   const common::crypto::SessionKey& macKey,
                                   const common::crypto::SessionKey& headerKey,
                                   uint64_t& outCounter) noexcept
    {
        const bool tagged = packet.IsTagged();
        const size_t headerSize = tagged
            ? internal::WIRE_SECURE_HEAD_SIZE + internal::WIRE_PEER_TAG_SIZE
            : internal::WIRE_SECURE_HEAD_SIZE;
        if (packet.dataSize < headerSize + internal::WIRE_TAG_SIZE)
            return false;

        const size_t covered = packet.dataSize - internal::WIRE_TAG_SIZE;
        common::crypto::Mac carried;
        std::memcpy(carried.data(), packet.data + covered, carried.size());

        // Unmask into a local, never back into the header: a wrong key here is
        // routine on the migration path, and a header mutated by a failed
        // attempt would poison the next one.
        uint8_t nonceField[internal::WIRE_NONCE_SIZE];
        std::memcpy(nonceField, packet.data + internal::WIRE_CONTROLLER_SIZE,
                    sizeof(nonceField));
        MaskNonceCounter(nonceField, headerKey, carried.data());
        const uint64_t counter = ReadNonceCounter(nonceField);

        // Recompute over the range as the sender built it, which means with the
        // counter unmasked. Restore it for the span of the check and put the
        // wire bytes back afterwards, so a failed attempt leaves the packet
        // exactly as it arrived.
        uint8_t masked[internal::WIRE_NONCE_SIZE];
        std::memcpy(masked, packet.data + internal::WIRE_CONTROLLER_SIZE, sizeof(masked));
        std::memcpy(packet.data + internal::WIRE_CONTROLLER_SIZE, nonceField, sizeof(nonceField));

        common::crypto::Mac expected;
        common::crypto::ComputeMac(expected, macKey, packet.data, covered);
        const bool ok = common::crypto::Equal(expected.data(), carried.data(), expected.size());

        if (!ok)
        {
            std::memcpy(packet.data + internal::WIRE_CONTROLLER_SIZE, masked, sizeof(masked));
            return false;
        }

        outCounter = counter;
        return true;
    }

    bool OpenSecurePacket(PacketSlot& packet,
                                   const common::crypto::SessionKey& key,
                                   const common::crypto::SessionKey& headerKey,
                                   uint8_t senderNonceLane,
                                   uint64_t& outCounter) noexcept
    {
        const bool tagged = packet.IsTagged();
        const size_t headerSize = tagged
            ? internal::WIRE_SECURE_HEAD_SIZE + internal::WIRE_PEER_TAG_SIZE
            : internal::WIRE_SECURE_HEAD_SIZE;
        if (packet.dataSize < headerSize + internal::WIRE_TAG_SIZE)
            return false;

        common::crypto::Tag tag;
        std::memcpy(tag.data(), packet.data + packet.dataSize - internal::WIRE_TAG_SIZE,
                    tag.size());

        // Unmask into a local, never back into the header: a wrong key here is
        // routine (the migration path tries every candidate against the same
        // packet), and a header mutated by a failed attempt would poison the
        // next one.
        uint8_t nonceField[internal::WIRE_NONCE_SIZE];
        std::memcpy(nonceField,
                    packet.data + internal::WIRE_CONTROLLER_SIZE,
                    sizeof(nonceField));
        MaskNonceCounter(nonceField, headerKey, tag.data());
        const uint64_t counter = ReadNonceCounter(nonceField);

        common::crypto::Nonce nonce;
        ExpandNonce(nonce, counter, senderNonceLane);

        uint8_t aad[internal::WIRE_CONTROLLER_SIZE + internal::WIRE_PEER_TAG_SIZE];
        const size_t aadLen = BuildSecureAad(
            aad, packet.data[0],
            tagged ? packet.data + internal::WIRE_SECURE_HEAD_SIZE : nullptr);

        uint8_t* body = packet.data + headerSize;
        const size_t bodyLen = packet.dataSize - headerSize - internal::WIRE_TAG_SIZE;
        if (!common::crypto::Decrypt(body, key, nonce, body, bodyLen, tag, aad, aadLen))
            return false;

        outCounter = counter;
        return true;
    }
}
