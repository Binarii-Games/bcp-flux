#pragma once

#include <cstddef>
#include <cstdint>

#include <common/crypto/crypto.h>
#include <common/result.h>

#include <flux/crypto/certificate.h>

namespace bcp::flux
{
    /** This node's long-term identity: the X25519 keypair that proves it owns
        its certificate, plus the identity tag it announces during the
        handshake. Produced by Generate, serialized to a private identity file,
        and loaded once at startup; held only here, so the secret half never
        goes on the wire and is never placed in a Certificate.

        The public half equals the certificate's subjectKey and the tag equals
        the certificate's tag, so one private file gives a server everything it
        needs. The public key is derived from the secret at parse time, so the
        two halves can never disagree. */
    struct Identity
    {
        /** Serialized private identity file: secret key + identity tag. The
            public key is derived, never written. The tag is public, but the file
            as a whole is secret because it carries the secret key. */
        static constexpr size_t FILE_SIZE =
            common::crypto::KEY_SIZE + Certificate::IDENTITY_TAG_SIZE;

        common::crypto::SecretKey secretKey{};   ///< secret, never leaves this process
        common::crypto::PublicKey publicKey{};   ///< derived; equals the certificate's subjectKey
        Certificate::IdentityTag  tag{};         ///< announced in the handshake; public

        /** Generates a fresh random identity carrying `tag`. Fails only if the
            system RNG does. */
        [[nodiscard]] static common::Result<Identity> Generate(const Certificate::IdentityTag& tag);

        /** The public certificate for this identity: version + public key + tag.
            This is the artifact distributed to clients. */
        [[nodiscard]] Certificate ToCertificate() const;

        /** Zeroes the secret key in memory. Call once the identity is no longer
            needed by the holder. */
        void Wipe() noexcept;

        /** Writes secret key then tag into `out` in a fixed byte order. Returns
            false if `cap` is below FILE_SIZE; nothing is written on failure. The
            output is secret material; the caller owns protecting its
            destination. */
        [[nodiscard]] bool Serialize(uint8_t* out, size_t cap) const;

        /** Parses secret key + tag from `in`, deriving the public half. Fails on
            a buffer shorter than FILE_SIZE. A failed result holds no identity. */
        [[nodiscard]] static common::Result<Identity> Parse(const uint8_t* in, size_t len);
    };
}
