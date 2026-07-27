#include <flux/crypto/cert_store.h>

#include <atomic>
#include <cstring>
#include <new>

#include <common/math.h>

namespace bcp::flux
{
    static_assert(std::is_trivially_copyable_v<Certificate>,
                  "Certificate is stored in a SlotPool by raw cast, so it must stay trivially copyable");

    namespace
    {
        /** Optimistic probes a Check makes before it serializes behind the
            writer lock. Retries happen only when an Add raced the probe, so the
            slow path stays untaken at sane write rates. It lets a continuously
            mutating writer delay a reader, not starve it. */
        constexpr uint32_t MAX_OPTIMISTIC_ATTEMPTS = 16;

        uint32_t Dist(uint64_t hash, uint32_t pos, uint32_t mask)
        {
            return (pos - (static_cast<uint32_t>(hash) & mask)) & mask;
        }
    }

    CertStore::~CertStore()
    {
        Shutdown();
    }

    common::Error CertStore::Init(uint32_t capacity)
    {
        if (capacity == 0)
            return common::Error::InvalidParam;

        const uint64_t need = (static_cast<uint64_t>(capacity) * 100 + MAX_LOAD_PERCENT - 1) / MAX_LOAD_PERCENT;
        if (need > (1u << 30))
            return common::Error::InvalidParam;

        idxCapacity_ = common::NextPowerOfTwo(static_cast<uint32_t>(need));
        idxMask_     = idxCapacity_ - 1;

        index_.reset(new (std::nothrow) IndexEntry[idxCapacity_]);
        if (!index_)
        {
            Shutdown();
            return common::Error::AllocFailed;
        }

        const uint32_t stride = static_cast<uint32_t>(
            (sizeof(Certificate) + common::CACHE_LINE - 1) & ~(common::CACHE_LINE - 1));
        if (!certPool_.Init(capacity, stride))
        {
            Shutdown();
            return common::Error::AllocFailed;
        }

        capacity_ = capacity;
        version_.store(0, std::memory_order_relaxed);
        count_.store(0, std::memory_order_relaxed);
        return common::Error::Ok;
    }

    void CertStore::Shutdown()
    {
        index_.reset();
        certPool_.Shutdown();
        idxCapacity_ = 0;
        idxMask_     = 0;
        capacity_    = 0;
        version_.store(0, std::memory_order_relaxed);
        count_.store(0, std::memory_order_relaxed);
    }

    common::Error CertStore::Add(const Certificate& cert)
    {
        if (!index_)
            return common::Error::NotInitialized;

        const uint64_t h = HashTag(cert.identityTag);

        LockWriter();

        // Writer-side probe; writeLock_ is held, so plain key reads are exact.
        {
            uint32_t pos  = static_cast<uint32_t>(h) & idxMask_;
            for (uint32_t dist = 0; ; ++dist)
            {
                const uint64_t eh = index_[pos].hash.load(std::memory_order_relaxed);
                if (eh == 0)
                    break;
                if (eh == h && index_[pos].key == cert.identityTag)
                {
                    // Same tag already stored: the new certificate supersedes it
                    // in place. The index is untouched (same hash, same slot), so
                    // no seqlock cycle; the slot's write lock alone keeps
                    // concurrent Checks reading a whole certificate, old or new.
                    const uint32_t slot = index_[pos].idx.load(std::memory_order_relaxed);
                    Certificate* c = reinterpret_cast<Certificate*>(certPool_.WriteLock(slot));
                    *c = cert;
                    certPool_.UnlockWrite(slot);
                    UnlockWriter();
                    return common::Error::Ok;
                }
                if (Dist(eh, pos, idxMask_) < dist)
                    break;
                pos = (pos + 1) & idxMask_;
            }
        }

        if (count_.load(std::memory_order_relaxed) >= capacity_)
        {
            UnlockWriter();
            return common::Error::LimitReached;
        }

        const uint32_t slot = certPool_.Acquire();
        if (slot == common::collections::SlotPool::INVALID)
        {
            UnlockWriter();
            return common::Error::LimitReached;
        }

        {
            Certificate* c = reinterpret_cast<Certificate*>(certPool_.WriteLock(slot));
            *c = cert;
            certPool_.UnlockWrite(slot);
        }

        // Robin Hood insert under an odd version, as PeerTable does it:
        // displacement moves entries between buckets, so a concurrent probe
        // must be able to prove it raced nothing.
        const uint32_t v = version_.load(std::memory_order_relaxed);
        version_.store(v + 1, std::memory_order_relaxed);
        std::atomic_thread_fence(std::memory_order_release);
        {
            uint64_t                 ch = h;
            uint32_t                 cs = slot;
            Certificate::IdentityTag ck = cert.identityTag;

            uint32_t pos  = static_cast<uint32_t>(ch) & idxMask_;
            uint32_t dist = 0;
            for (;;)
            {
                IndexEntry& e = index_[pos];
                const uint64_t eh = e.hash.load(std::memory_order_relaxed);
                if (eh == 0)
                {
                    e.idx.store(cs, std::memory_order_relaxed);
                    e.key = ck;
                    e.hash.store(ch, std::memory_order_relaxed);
                    break;
                }

                const uint32_t ed = Dist(eh, pos, idxMask_);
                if (ed < dist)
                {
                    const uint32_t                 ts = e.idx.load(std::memory_order_relaxed);
                    const Certificate::IdentityTag tk = e.key;
                    e.idx.store(cs, std::memory_order_relaxed);
                    e.key = ck;
                    e.hash.store(ch, std::memory_order_relaxed);
                    ch = eh;
                    cs = ts;
                    ck = tk;
                    dist = ed;
                }

                pos = (pos + 1) & idxMask_;
                ++dist;
            }
        }
        version_.store(v + 2, std::memory_order_release);

        count_.fetch_add(1, std::memory_order_relaxed);
        UnlockWriter();
        return common::Error::Ok;
    }

    CertStore::Match CertStore::Check(const Certificate::IdentityTag& tag,
                                      const common::crypto::PublicKey& presentedKey) const
    {
        if (!index_)
            return Match::NotFound;

        const uint64_t h = HashTag(tag);

        for (uint32_t attempt = 0; attempt < MAX_OPTIMISTIC_ATTEMPTS; ++attempt)
        {
            const uint32_t v1 = version_.load(std::memory_order_acquire);
            if (v1 & 1u)
            {
                common::CpuPause();
                continue;
            }

            bool retry = false;
            uint32_t pos = static_cast<uint32_t>(h) & idxMask_;
            for (uint32_t dist = 0; dist < idxCapacity_; ++dist)
            {
                const IndexEntry& e = index_[pos];
                const uint64_t eh = e.hash.load(std::memory_order_relaxed);
                if (eh == 0)
                    break;

                if (eh == h)
                {
                    const uint32_t idx = e.idx.load(std::memory_order_relaxed);
                    Match m = Match::NotFound;
                    if (ResolveSlot(idx, tag, presentedKey, m))
                    {
                        // Slots are never freed, so a tag verified inside the
                        // slot is definitive. The probe that led here may still
                        // have raced a displacement, so prove it didn't.
                        std::atomic_thread_fence(std::memory_order_acquire);
                        if (version_.load(std::memory_order_relaxed) == v1)
                            return m;
                        retry = true;
                        break;
                    }
                    // Same 64-bit hash, different tag: keep probing.
                }
                else if (Dist(eh, pos, idxMask_) < dist)
                {
                    break;
                }

                pos = (pos + 1) & idxMask_;
            }
            if (retry)
                continue;

            std::atomic_thread_fence(std::memory_order_acquire);
            if (version_.load(std::memory_order_relaxed) == v1)
                return Match::NotFound;
        }

        // Slow path: probe under the writer lock, which excludes every index
        // mutation, so no version dance is needed. Guarantees reader progress
        // under a continuously-mutating writer.
        LockWriter();

        Match result = Match::NotFound;
        uint32_t pos = static_cast<uint32_t>(h) & idxMask_;
        for (uint32_t dist = 0; dist < idxCapacity_; ++dist)
        {
            const IndexEntry& e = index_[pos];
            const uint64_t eh = e.hash.load(std::memory_order_relaxed);
            if (eh == 0)
                break;

            if (eh == h)
            {
                const uint32_t idx = e.idx.load(std::memory_order_relaxed);
                Match m = Match::NotFound;
                if (ResolveSlot(idx, tag, presentedKey, m))
                {
                    result = m;
                    break;
                }
            }
            else if (Dist(eh, pos, idxMask_) < dist)
            {
                break;
            }

            pos = (pos + 1) & idxMask_;
        }

        UnlockWriter();
        return result;
    }

    bool CertStore::ResolveSlot(uint32_t slot,
                                const Certificate::IdentityTag& tag,
                                const common::crypto::PublicKey& presentedKey,
                                Match& out) const
    {
        const Certificate* c = reinterpret_cast<const Certificate*>(certPool_.ReadLock(slot));
        const bool tagMatches =
            std::memcmp(c->identityTag.data(), tag.data(), tag.size()) == 0;
        if (tagMatches)
        {
            out = common::crypto::Equal(c->subjectKey.data(), presentedKey.data(),
                                        presentedKey.size())
                ? Match::Trusted
                : Match::Mismatch;
        }
        certPool_.UnlockRead(slot);
        return tagMatches;
    }

    uint64_t CertStore::HashTag(const Certificate::IdentityTag& tag)
    {
        // Tags are hashes already, so their first 8 bytes are uniform.
        uint64_t h;
        std::memcpy(&h, tag.data(), sizeof(h));
        return h ? h : 1;
    }

    void CertStore::LockWriter() const noexcept
    {
        while (writeLock_.test_and_set(std::memory_order_acquire))
            common::CpuPause();
    }

    void CertStore::UnlockWriter() const noexcept
    {
        writeLock_.clear(std::memory_order_release);
    }
}
