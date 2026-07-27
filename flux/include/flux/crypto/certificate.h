#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include <common/crypto/crypto.h>
#include <common/result.h>

namespace bcp::flux
{
    /** A pinned identity: a peer's long-term X25519 public key bound to an
        opaque identity tag. Certificates are provisioned directly in this
        phase (embedded in a client, loaded from config) and trusted by that
        provisioning: the holder pins the key, and the handshake proves the
        peer owns the matching secret. Trust comes from delivery, not a
        signature, so none is carried here.

        The leading version selects the layout. Only VERSION_PINNED exists
        today; it reserves the position for a later authority-signed layout,
        without invalidating certificates already in the field.

        The identity tag is opaque to Flux. It is stored and surfaced to the
        layer above, which alone gives it meaning (conventionally a hash of
        that layer's name for the subject). Flux never parses, compares, or
        interprets it. */
    struct Certificate
    {
        using IdentityTag = std::array<uint8_t, 32>;

        static constexpr size_t IDENTITY_TAG_SIZE = 32;

        /** Pinned, unsigned: version + subject key + identity tag. */
        static constexpr uint8_t VERSION_PINNED = 1;

        /** Serialized size of a VERSION_PINNED certificate on disk / in config. */
        static constexpr size_t PINNED_SIZE =
            1 + common::crypto::KEY_SIZE + IDENTITY_TAG_SIZE;

        uint8_t                   version = VERSION_PINNED;
        common::crypto::PublicKey subjectKey{};   ///< the peer's pinned X25519 key
        IdentityTag               identityTag{};  ///< opaque; meaning lives above Flux

        /** Writes the certificate into `out` using a fixed, explicit byte
            order. Returns false if `cap` is below the serialized size; on
            failure nothing is written and no partial output is left behind. */
        [[nodiscard]] bool Serialize(uint8_t* out, size_t cap) const;

        /** Parses a certificate from `in`. Fails on a buffer shorter than the
            version requires, or on an unrecognized version. A failed result
            holds no certificate; a partial parse is never returned. */
        [[nodiscard]] static common::Result<Certificate> Parse(const uint8_t* in, size_t len);
    };
}
