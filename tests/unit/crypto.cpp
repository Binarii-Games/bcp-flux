// Crypto floor integrity. The wrapper around monocypher must give the two
// properties Flux relies on: both sides of a Diffie-Hellman exchange land on
// the same secret, and authenticated encryption round-trips but rejects any
// tampering. These assert behaviour (agreement, recovery, rejection), not the
// primitive's internals.
#include <common/crypto/crypto.h>

#include "harness.h"

#include <array>
#include <cstring>

namespace crypto = bcp::common::crypto;

// Two peers running X25519 over each other's public key reach the same shared
// secret, and a third party's key yields a different one (so the secret really
// depends on the keys, not a constant).
static void dh_agrees_on_shared_secret()
{
    crypto::SecretKey secretA, secretB, secretC;
    crypto::PublicKey publicA, publicB, publicC;
    CHECK(crypto::GenerateKeypair(secretA, publicA));
    CHECK(crypto::GenerateKeypair(secretB, publicB));
    CHECK(crypto::GenerateKeypair(secretC, publicC));

    crypto::SharedSecret fromA, fromB;
    crypto::ComputeSharedSecret(fromA, secretA, publicB);
    crypto::ComputeSharedSecret(fromB, secretB, publicA);
    CHECK(crypto::Equal(fromA.data(), fromB.data(), crypto::SHARED_SIZE));

    // A's secret against a stranger's key must not land on the same value.
    crypto::SharedSecret withStranger;
    crypto::ComputeSharedSecret(withStranger, secretA, publicC);
    CHECK(!crypto::Equal(fromA.data(), withStranger.data(), crypto::SHARED_SIZE));
}

// The KDF is deterministic for the same input, and binding a context changes
// the derived key (so a transcript can bind the session key to the handshake).
static void session_key_is_deterministic_and_context_bound()
{
    crypto::SharedSecret shared{};
    for (size_t i = 0; i < shared.size(); ++i) shared[i] = static_cast<uint8_t>(i);

    crypto::SessionKey plain1, plain2;
    crypto::DeriveSessionKey(plain1, shared);
    crypto::DeriveSessionKey(plain2, shared);
    CHECK(crypto::Equal(plain1.data(), plain2.data(), crypto::KEY_SIZE));   // deterministic

    const uint8_t contextA[] = {'f', 'l', 'u', 'x', 'A'};
    const uint8_t contextB[] = {'f', 'l', 'u', 'x', 'B'};
    crypto::SessionKey boundA, boundB;
    crypto::DeriveSessionKey(boundA, shared, contextA, sizeof(contextA));
    crypto::DeriveSessionKey(boundB, shared, contextB, sizeof(contextB));
    CHECK(!crypto::Equal(boundA.data(), boundB.data(), crypto::KEY_SIZE));  // context binds
    CHECK(!crypto::Equal(plain1.data(), boundA.data(), crypto::KEY_SIZE));  // context vs none
}

// Encrypt then decrypt recovers the plaintext, and the ciphertext is not the
// plaintext.
static void aead_round_trips()
{
    crypto::SessionKey key{};
    crypto::Nonce      nonce{};
    for (size_t i = 0; i < key.size();   ++i) key[i]   = static_cast<uint8_t>(0x10 + i);
    for (size_t i = 0; i < nonce.size(); ++i) nonce[i] = static_cast<uint8_t>(0x40 + i);

    const uint8_t plain[] = {'f', 'l', 'u', 'x', ' ', 'p', 'a', 'y', 'l', 'o', 'a', 'd'};
    constexpr size_t LEN = sizeof(plain);

    uint8_t      cipher[LEN];
    crypto::Tag  tag;
    crypto::Encrypt(cipher, tag, key, nonce, plain, LEN);
    CHECK(std::memcmp(cipher, plain, LEN) != 0);   // actually encrypted

    uint8_t recovered[LEN];
    CHECK(crypto::Decrypt(recovered, key, nonce, cipher, LEN, tag));
    CHECK(std::memcmp(recovered, plain, LEN) == 0);
}

// A flipped ciphertext byte or a flipped tag byte fails authentication.
static void aead_rejects_tampering()
{
    crypto::SessionKey key{};
    crypto::Nonce      nonce{};
    for (size_t i = 0; i < key.size();   ++i) key[i]   = static_cast<uint8_t>(0x10 + i);
    for (size_t i = 0; i < nonce.size(); ++i) nonce[i] = static_cast<uint8_t>(0x40 + i);

    const uint8_t plain[] = {'s', 'e', 'c', 'r', 'e', 't'};
    constexpr size_t LEN = sizeof(plain);

    uint8_t     cipher[LEN];
    crypto::Tag tag;
    crypto::Encrypt(cipher, tag, key, nonce, plain, LEN);

    uint8_t recovered[LEN];

    uint8_t tamperedCipher[LEN];
    std::memcpy(tamperedCipher, cipher, LEN);
    tamperedCipher[0] ^= 0x01;
    CHECK(!crypto::Decrypt(recovered, key, nonce, tamperedCipher, LEN, tag));

    crypto::Tag tamperedTag = tag;
    tamperedTag[0] ^= 0x01;
    CHECK(!crypto::Decrypt(recovered, key, nonce, cipher, LEN, tamperedTag));
}

// Associated data is authenticated but not encrypted: decryption succeeds only
// when the same AD is supplied.
static void aead_binds_associated_data()
{
    crypto::SessionKey key{};
    crypto::Nonce      nonce{};
    for (size_t i = 0; i < key.size();   ++i) key[i]   = static_cast<uint8_t>(0x10 + i);
    for (size_t i = 0; i < nonce.size(); ++i) nonce[i] = static_cast<uint8_t>(0x40 + i);

    const uint8_t plain[]     = {'b', 'o', 'd', 'y'};
    const uint8_t header[]    = {0x04, 0x01};   // stands in for a cleartext controller byte
    constexpr size_t LEN = sizeof(plain);

    uint8_t     cipher[LEN];
    crypto::Tag tag;
    crypto::Encrypt(cipher, tag, key, nonce, plain, LEN, header, sizeof(header));

    uint8_t recovered[LEN];
    CHECK(crypto::Decrypt(recovered, key, nonce, cipher, LEN, tag, header, sizeof(header)));

    uint8_t wrongHeader[] = {0x04, 0x02};
    CHECK(!crypto::Decrypt(recovered, key, nonce, cipher, LEN, tag, wrongHeader, sizeof(wrongHeader)));
}

// A self-certifying id verifies against its own public key and no other.
static void id_verifies_against_its_key()
{
    crypto::SecretKey secretA, secretB;
    crypto::PublicKey publicA, publicB;
    CHECK(crypto::GenerateKeypair(secretA, publicA));
    CHECK(crypto::GenerateKeypair(secretB, publicB));

    crypto::Id id;
    crypto::DeriveId(id, publicA);
    CHECK(crypto::VerifyId(id, publicA));
    CHECK(!crypto::VerifyId(id, publicB));
}

// Constant-time compare reports equal buffers as equal and a one-byte
// difference as unequal.
static void equal_compares_by_value()
{
    std::array<uint8_t, 32> reference{}, altered{};
    for (size_t i = 0; i < reference.size(); ++i)
    {
        reference[i] = static_cast<uint8_t>(i);
        altered[i]   = reference[i];
    }
    CHECK(crypto::Equal(reference.data(), altered.data(), reference.size()));

    altered[15] ^= 0x01;
    CHECK(!crypto::Equal(reference.data(), altered.data(), reference.size()));
}

int main()
{
    dh_agrees_on_shared_secret();
    session_key_is_deterministic_and_context_bound();
    aead_round_trips();
    aead_rejects_tampering();
    aead_binds_associated_data();
    id_verifies_against_its_key();
    equal_compares_by_value();
    return test::report();
}
