#pragma once

#include <cstdint>
#include <atomic>

#include <common/platform.h>
#include <common/error.h>
#include <common/crypto/crypto.h>

#include <flux/crypto/certificate.h>
#include <flux/crypto/identity.h>
#include <flux/internal/constants.h>

namespace bcp::flux
{
    /** The keypairs this socket answers on: the one it presents now, and the
        ones it presented before, kept so a peer whose certificate has not
        caught up can still be reached.

        The tag never moves. It is the durable identity and a rotation only
        changes which key currently proves it, so every peer relationship
        survives one and only the proof is replaced.

        A keypair is named on the wire by a four-byte id derived from its
        public half. A first-flight opener says which key it was encrypted
        toward and the receiver picks that one, instead of attempting a key
        agreement against each key it holds, which would let an unauthenticated
        packet cost as much work as this socket keeps history. Anyone holding
        the certificate can compute the id, which is exactly who needs to.

        Reads take a short lock rather than running optimistically. Only two
        callers read: the send path when it arms an opener, and the receive
        path when it opens one, and the second of those is already serialised
        behind the socket's update gate. So the lock is uncontended in
        practice, and it costs less than the alternative costs in subtlety. */
    class IdentityTable
    {
    public:
        /** One keypair and the id that names it, copied out to the caller so
            no lock is held across a key agreement. */
        struct Entry
        {
            common::crypto::SecretKey secretKey{};
            common::crypto::PublicKey publicKey{};
            uint32_t                  keyId = 0;
        };

        /** What a looked-up id turned out to be. Previous means the peer that
            named it is working from a certificate this socket has replaced,
            which is answerable but worth telling the application about. */
        enum class Which : uint8_t
        {
            None,       ///< no held key carries this id
            Current,    ///< the key this socket presents now
            Previous,   ///< a retained key, so the caller's certificate is stale
        };

        /** Asks for the current keypair rather than a named one. No derived id
            collides with it because KeyIdOf never returns zero. */
        static constexpr uint32_t CURRENT = 0;

        IdentityTable() = default;
        ~IdentityTable();

        IdentityTable(const IdentityTable&) = delete;
        IdentityTable& operator=(const IdentityTable&) = delete;

        /** The four bytes that name a key on the wire: the leading bytes of
            the hash the peer id already comes from, so there is one derivation
            of a key's name and not two. Remapped away from zero, which is
            reserved for CURRENT. */
        [[nodiscard]] static uint32_t KeyIdOf(const common::crypto::PublicKey& pk) noexcept;

        /** Installs the first keypair and fixes how many previous ones are
            kept past a rotation. InvalidParam when history exceeds
            internal::MAX_IDENTITY_HISTORY. */
        [[nodiscard]] common::Error Init(const Identity& first, uint8_t history);

        /** Wipes every secret. Idempotent.
            @warning Not safe while other threads still use the table. */
        void Shutdown() noexcept;

        /** Makes next the current keypair and pushes the previous one down,
            dropping the oldest once the history is full. Safe to call under
            live traffic. InvalidParam when next carries a different tag,
            because the tag is the identity and only the key rotates. */
        common::Error Rotate(const Identity& next);

        /** Wipes every keypair but the current one, so an opener aimed at any
            of them stops being answerable. Safe under live traffic. This is
            the leak response: the peers still working from those certificates
            are cut off, which is the intended outcome and not a side effect. */
        void ForgetPrevious() noexcept;

        /** Copies the keypair this id names into out and says which it was.
            CURRENT asks for the key presented now. None leaves out untouched
            and means the id names a key already forgotten, or no key at all.
            Safe under any concurrency with Rotate and ForgetPrevious. */
        [[nodiscard]] Which Find(uint32_t keyId, Entry& out) const noexcept;

        /** The tag every one of these keypairs proves. Fixed at Init. */
        [[nodiscard]] const Certificate::IdentityTag& Tag() const noexcept { return tag_; }

        /** Keypairs held, the current one included. */
        [[nodiscard]] uint8_t Count() const noexcept;

    private:
        /** Newest first: entries_[0] is current, the rest are retained in the
            order they were replaced. Guarded by lock_, which both readers and
            writers take, so nothing here is atomic. */
        Entry                    entries_[1 + internal::MAX_IDENTITY_HISTORY];
        uint8_t                  count_    = 0;
        uint8_t                  capacity_ = 0;   ///< 1 + the configured history
        Certificate::IdentityTag tag_{};          ///< never rotates

        alignas(common::CACHE_LINE) mutable std::atomic_flag lock_ = ATOMIC_FLAG_INIT;

        void Lock() const noexcept;
        void Unlock() const noexcept;
    };
}
