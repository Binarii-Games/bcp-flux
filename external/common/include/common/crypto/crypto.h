#pragma once

#include <cstdint>
#include <cstddef>
#include <array>

#include <monocypher.h>
#include <common/platform.h>

// Platform secure RNG. Windows: BCryptGenRandom. Apple: arc4random_buf,
// because iOS has no sys/random.h. Linux: getrandom.
#if defined(_WIN32)
    #include <bcrypt.h>
    #pragma comment(lib, "bcrypt.lib")
#elif defined(__APPLE__)
    #include <stdlib.h>       // arc4random_buf, on macOS and iOS alike
#else
    #include <sys/random.h>   // getrandom
#endif

// Single-file, clearly-named wrapper over monocypher.
//
// monocypher's names are terse and easy to misuse. This maps them to
// intention-revealing names and fixed-size types:
//
//   GenerateSecretKey / DerivePublicKey   -> X25519 keypair
//   ComputeSharedSecret                   -> X25519 DH (key mixing)
//   DeriveSessionKey                      -> KDF (blake2b) over the shared secret
//   DeriveId / VerifyId                   -> 256-bit self-certifying id = blake2b(pubkey)
//   Encrypt / Decrypt                     -> AEAD lock/unlock
//   Wipe / Equal                          -> crypto_wipe / constant-time compare
//
// Header-only: all functions inline. Sizes fixed by the primitives
// (X25519 = 32, AEAD tag = 16, XChaCha nonce = 24).

namespace bcp::common::crypto
{
    inline constexpr size_t KEY_SIZE    = 32;  ///< X25519 keys, AEAD key, session key
    inline constexpr size_t ID_SIZE     = 32;  ///< 256-bit node id
    inline constexpr size_t NONCE_SIZE  = 24;  ///< XChaCha20 nonce
    inline constexpr size_t TAG_SIZE    = 16;  ///< Poly1305 auth tag (MAC)
    inline constexpr size_t SHARED_SIZE = 32;  ///< X25519 shared secret
    inline constexpr size_t MAC_SIZE    = 16;  ///< keyed-blake2b message MAC

    using SecretKey    = std::array<uint8_t, KEY_SIZE>;
    using PublicKey    = std::array<uint8_t, KEY_SIZE>;
    using SessionKey   = std::array<uint8_t, KEY_SIZE>;
    using SharedSecret = std::array<uint8_t, SHARED_SIZE>;
    using Nonce        = std::array<uint8_t, NONCE_SIZE>;
    using Tag          = std::array<uint8_t, TAG_SIZE>;
    using Id           = std::array<uint8_t, ID_SIZE>;
    using Mac          = std::array<uint8_t, MAC_SIZE>;

    // --- Hygiene ---

    /** Securely zero a secret buffer. Not optimized away. */
    inline void Wipe(void* secret, size_t len) noexcept
    {
        crypto_wipe(secret, len);
    }

    /** Constant-time equality, no timing leak. Returns true if equal. */
    inline bool Equal(const uint8_t* a, const uint8_t* b, size_t len) noexcept
    {
        switch (len)
        {
            case 16: return crypto_verify16(a, b) == 0;
            case 32: return crypto_verify32(a, b) == 0;
            case 64: return crypto_verify64(a, b) == 0;
            default: break;
        }
        uint8_t diff = 0;
        for (size_t i = 0; i < len; ++i) diff |= (uint8_t)(a[i] ^ b[i]);
        return diff == 0;
    }

    // --- Randomness ---

    /** Fill buffer with cryptographically secure random bytes.

        @return false if the platform RNG failed; the caller must check. */
    [[nodiscard]] inline bool RandomBytes(uint8_t* out, size_t len) noexcept
    {
    #if defined(_WIN32)
        NTSTATUS s = BCryptGenRandom(
            nullptr, out, static_cast<ULONG>(len),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        return s == 0; // STATUS_SUCCESS
    #elif defined(__APPLE__)
        // Kernel CSPRNG with no failure path and no length cap.
        arc4random_buf(out, len);
        return true;
    #else
        size_t done = 0;
        while (done < len)
        {
            ssize_t n = getrandom(out + done, len - done, 0);
            if (n < 0) return false;
            done += static_cast<size_t>(n);
        }
        return true;
    #endif
    }

    // --- Key generation ---

    /** Generate a fresh random X25519 secret key. Returns false on RNG failure.

        X25519 accepts any 32 random bytes and clamps internally. */
    [[nodiscard]] inline bool GenerateSecretKey(SecretKey& sk) noexcept
    {
        return RandomBytes(sk.data(), sk.size());
    }

    /** Derive the public key from a secret key (X25519 base-point mul). */
    inline void DerivePublicKey(PublicKey& pk, const SecretKey& sk) noexcept
    {
        crypto_x25519_public_key(pk.data(), sk.data());
    }

    /** Generate sk and derive pk in one call. Returns false on RNG failure. */
    [[nodiscard]] inline bool GenerateKeypair(SecretKey& sk, PublicKey& pk) noexcept
    {
        if (!GenerateSecretKey(sk)) return false;
        DerivePublicKey(pk, sk);
        return true;
    }

    // --- Key agreement ---

    /** X25519 Diffie-Hellman: combine your secret with their public to get the
        shared secret. Both sides compute the same value.

        @warning Raw DH output is not a key. Feed it to DeriveSessionKey. */
    inline void ComputeSharedSecret(SharedSecret& out,
                                    const SecretKey& mySk,
                                    const PublicKey& theirPk) noexcept
    {
        crypto_x25519(out.data(), mySk.data(), theirPk.data());
    }

    /** KDF: turn a raw shared secret into a usable symmetric session key
        (blake2b over the shared secret). Optionally bind extra context
        (e.g. both public keys or a transcript) via context. */
    inline void DeriveSessionKey(SessionKey& out,
                                 const SharedSecret& shared,
                                 const uint8_t* context = nullptr,
                                 size_t contextLen = 0) noexcept
    {
        if (context && contextLen)
        {
            crypto_blake2b_keyed(out.data(), out.size(),
                                 shared.data(), shared.size(),
                                 context, contextLen);
        }
        else
        {
            crypto_blake2b(out.data(), out.size(),
                           shared.data(), shared.size());
        }
    }

    /** Derives a 32-byte subkey from a key and a 16-byte input (HChaCha20: one
        permutation, no setup, so it is cheap enough for a per-packet call).
        Distinct inputs give unrelated subkeys, and the key cannot be recovered
        from them, so this is the primitive for splitting one shared secret into
        purpose-specific keys — or for producing an unpredictable per-message
        value from something an observer can already see.

        @warning Not a KDF for password or low-entropy material; `key` must
                 already be a uniform secret. */
    inline void DeriveSubKey(uint8_t out[KEY_SIZE], const uint8_t key[KEY_SIZE],
                             const uint8_t input[16]) noexcept
    {
        crypto_chacha20_h(out, key, input);
    }

    /** Keyed MAC (blake2b) over an arbitrary message. Proves the producer holds
        key and that the message is unchanged. For example a handshake
        confirmation over the transcript, keyed by the derived session key.

        @warning Verify with Equal() on MAC_SIZE, never operator== on raw bytes. */
    inline void ComputeMac(Mac& out, const SessionKey& key,
                           const uint8_t* msg, size_t len) noexcept
    {
        crypto_blake2b_keyed(out.data(), out.size(),
                             key.data(), key.size(),
                             msg, len);
    }

    // --- Identity ---

    /** Derive the 256-bit self-certifying node id: id = blake2b(pubkey).
        Deterministic (no salt) so any node can recompute and verify it. */
    inline void DeriveId(Id& out, const PublicKey& pk) noexcept
    {
        crypto_blake2b(out.data(), out.size(), pk.data(), pk.size());
    }

    /** Verify a claimed id matches a presented public key (constant-time). */
    [[nodiscard]] inline bool VerifyId(const Id& claimed, const PublicKey& pk) noexcept
    {
        Id computed;
        DeriveId(computed, pk);
        bool ok = Equal(claimed.data(), computed.data(), ID_SIZE);
        Wipe(computed.data(), computed.size());
        return ok;
    }

    // --- AEAD encryption ---

    /** Encrypt plain (len bytes) into cipher (same len) under key and nonce,
        producing a 16-byte tag. ad is additional authenticated data
        (authenticated, not encrypted, e.g. the cleartext controller byte).

        @note cipher may alias plain for in-place encryption. */
    inline void Encrypt(uint8_t* cipher, Tag& tag,
                        const SessionKey& key, const Nonce& nonce,
                        const uint8_t* plain, size_t len,
                        const uint8_t* ad = nullptr, size_t adLen = 0) noexcept
    {
        crypto_aead_lock(cipher, tag.data(),
                         key.data(), nonce.data(),
                         ad, adLen,
                         plain, len);
    }

    /** Decrypt and verify. Returns false if the tag is invalid (forged or tampered);
        plain is not trusted in that case. ad must match what was encrypted.

        @note plain may alias cipher for in-place decryption. */
    [[nodiscard]] inline bool Decrypt(uint8_t* plain,
                                      const SessionKey& key, const Nonce& nonce,
                                      const uint8_t* cipher, size_t len, const Tag& tag,
                                      const uint8_t* ad = nullptr, size_t adLen = 0) noexcept
    {
        int rc = crypto_aead_unlock(plain, tag.data(),
                                    key.data(), nonce.data(),
                                    ad, adLen,
                                    cipher, len);
        return rc == 0; // 0 = ok, -1 = tag failed
    }
}
