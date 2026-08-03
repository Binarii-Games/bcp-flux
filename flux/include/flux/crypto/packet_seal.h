#pragma once

#include <cstddef>
#include <cstdint>

#include <common/crypto/crypto.h>

#include <flux/peer/peer.h>
#include <flux/socket/packet_slot.h>

namespace bcp::flux
{
    /** Sealing and opening a packet, and nothing else.

        Every outbound secure packet passes through one of the two seals here
        and every inbound one through the matching open. Keeping them together
        is what makes it checkable that the framing they write and the framing
        they read are the same framing, because the four are the only code that
        knows the layout.

        Nothing here reaches a peer, a flow, a pool or a socket. The session
        material a seal needs arrives by value in PeerSendMaterials, gathered by
        the caller under the peer's lock and carried in, so a seal never has to
        take a lock and can never take the wrong one. */

    /** What one send needs from its peer, gathered once under the peer's write
        lock and carried by value. Trivially copyable. The caller wipes `key`
        once the send is done with it. */
    struct PeerSendMaterials
    {
        common::crypto::SessionKey key;
        common::crypto::SessionKey headerKey;   ///< masks the wire counter field
        common::crypto::SessionKey macKey;      ///< authenticates a MAC-only packet
        uint64_t                   counter = 0;   ///< a fresh ++sendCounter per send
        uint8_t                    lane    = 0;
        PeerTag                    tag{};
    };

    /** Encrypts the body in place and appends the authentication tag.

        `headerSize` is where the body starts, which the caller already knows
        because it wrote the header. `tagged` says the peer-tag field is present,
        which changes both the offset and what the tag covers. */
    void SealSecurePacket(PacketSlot& dst, const uint8_t* plaintext,
                          size_t headerSize, size_t bodyLen,
                          const PeerSendMaterials& materials, bool tagged) noexcept;

    /** Leaves the body readable and appends the same authentication tag.

        Same framing as an encrypted packet to the byte, so every offset matches
        and only the protection differs. For traffic that is public anyway and
        sent often enough that halving the crypto is worth more than hiding it. */
    void SealMacOnlyPacket(PacketSlot& dst, size_t headerSize, size_t bodyLen,
                           const PeerSendMaterials& materials, bool tagged) noexcept;

    /** Decrypts in place and reports the sender's counter in `outCounter`.

        The counter is masked on the wire and this is the only place it is
        recovered. On failure the packet is left byte for byte as it arrived,
        which is what lets the migration path try one candidate key after
        another against the same bytes.

        @return false if the tag does not verify. `outCounter` means nothing
                then. */
    [[nodiscard]] bool OpenSecurePacket(PacketSlot& packet,
                                        const common::crypto::SessionKey& key,
                                        const common::crypto::SessionKey& headerKey,
                                        uint8_t senderLane,
                                        uint64_t& outCounter) noexcept;

    /** Verifies a MAC-only packet and reports the sender's counter. Same
        contract as OpenSecurePacket, including leaving the bytes untouched on
        failure. */
    [[nodiscard]] bool OpenMacOnlyPacket(PacketSlot& packet,
                                         const common::crypto::SessionKey& macKey,
                                         const common::crypto::SessionKey& headerKey,
                                         uint64_t& outCounter) noexcept;
}
