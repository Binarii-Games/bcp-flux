#include <flux/crypto/identity_table.h>

#include <cstring>

#include <flux/peer/peer_id.h>

namespace bcp::flux
{
    IdentityTable::~IdentityTable()
    {
        Shutdown();
    }

    uint32_t IdentityTable::KeyIdOf(const common::crypto::PublicKey& pk) noexcept
    {
        const BcpId id = BcpId::Derive(pk);
        uint32_t keyId = 0;
        for (size_t i = 0; i < sizeof(keyId); ++i)
            keyId |= static_cast<uint32_t>(id.id[i]) << (8 * i);
        return keyId != CURRENT ? keyId : 1;
    }

    common::Error IdentityTable::Init(const Identity& first, uint8_t history)
    {
        if (history > internal::MAX_IDENTITY_HISTORY)
            return common::Error::InvalidParam;

        capacity_ = static_cast<uint8_t>(1 + history);
        tag_      = first.tag;

        entries_[0].secretKey = first.secretKey;
        entries_[0].publicKey = first.publicKey;
        entries_[0].keyId     = KeyIdOf(first.publicKey);
        count_                = 1;
        return common::Error::Ok;
    }

    void IdentityTable::Shutdown() noexcept
    {
        for (uint8_t i = 0; i < count_; ++i)
        {
            common::crypto::Wipe(entries_[i].secretKey.data(), entries_[i].secretKey.size());
            entries_[i] = Entry{};
        }
        count_ = 0;
    }

    common::Error IdentityTable::Rotate(const Identity& next)
    {
        if (next.tag != tag_)
            return common::Error::InvalidParam;

        Lock();
        // The oldest goes first when the history is full, so the shift below
        // never runs off the end and the secret it drops is wiped rather than
        // left behind in a slot nobody reads.
        if (count_ == capacity_)
        {
            Entry& oldest = entries_[count_ - 1];
            common::crypto::Wipe(oldest.secretKey.data(), oldest.secretKey.size());
            --count_;
        }
        for (uint8_t i = count_; i > 0; --i)
            entries_[i] = entries_[i - 1];

        entries_[0].secretKey = next.secretKey;
        entries_[0].publicKey = next.publicKey;
        entries_[0].keyId     = KeyIdOf(next.publicKey);
        ++count_;
        Unlock();
        return common::Error::Ok;
    }

    void IdentityTable::ForgetPrevious() noexcept
    {
        Lock();
        for (uint8_t i = 1; i < count_; ++i)
        {
            common::crypto::Wipe(entries_[i].secretKey.data(), entries_[i].secretKey.size());
            entries_[i] = Entry{};
        }
        count_ = count_ != 0 ? 1 : 0;
        Unlock();
    }

    IdentityTable::Which IdentityTable::Find(uint32_t keyId, Entry& out) const noexcept
    {
        Lock();
        Which which = Which::None;
        if (count_ != 0 && (keyId == CURRENT || keyId == entries_[0].keyId))
        {
            out   = entries_[0];
            which = Which::Current;
        }
        else
        {
            for (uint8_t i = 1; i < count_; ++i)
            {
                if (entries_[i].keyId != keyId) continue;
                out   = entries_[i];
                which = Which::Previous;
                break;
            }
        }
        Unlock();
        return which;
    }

    uint8_t IdentityTable::Count() const noexcept
    {
        Lock();
        const uint8_t n = count_;
        Unlock();
        return n;
    }

    void IdentityTable::Lock() const noexcept
    {
        while (lock_.test_and_set(std::memory_order_acquire))
            common::CpuPause();
    }

    void IdentityTable::Unlock() const noexcept
    {
        lock_.clear(std::memory_order_release);
    }
}
