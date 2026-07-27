#pragma once

#include <atomic>
#include <cstdint>
#include <memory>

#include <common/platform.h>
#include <common/error.h>
#include <common/crypto/crypto.h>
#include <common/collections/slot_pool.h>

#include <flux/crypto/certificate.h>

namespace bcp::flux
{
    /** Fixed-capacity, allocation-free store of trusted certificates, the
        single-index sibling of PeerTable. Certificates live in a SlotPool and
        never move; one open-addressed Robin Hood index maps an identity tag to
        its slot. Concurrency matches PeerTable: a table-wide seqlock (version_)
        writers hold odd across index mutation and readers validate their whole
        probe against, a single writer serialized on writeLock_, and per-slot RW
        locks guarding the certificate bytes.

        Adds are rare (setup, or a resolver pushing a certificate); Check runs
        once per handshake. Adding an already-stored tag replaces that tag's
        certificate in place, so a rotated key supersedes the old one. Nothing is
        ever removed: trust is superseded, not unloaded, so slots are never
        recycled and the index needs no backward-shift path.

        Trust is by pinned key: a peer is authenticated only when it announces a
        tag this store holds AND presents that tag's certified key. The store
        never interprets a tag, only matches it. */
    class CertStore
    {
    public:
        /** Outcome of checking a peer's announced identity against the store. */
        enum class Match : uint8_t
        {
            NotFound,   ///< No certificate carries this tag; opportunistic only.
            Trusted,    ///< A certificate carries this tag AND this key; verified.
            Mismatch,   ///< A certificate carries this tag but a DIFFERENT key:
                        ///< an impersonation attempt or a stale/wrong certificate.
        };

        /** Same rationale as PeerTable: Robin Hood probe length degrades as the
            index saturates, so it is sized past the certificate capacity and
            never exceeds this load. The pool runs out first. */
        static constexpr uint32_t MAX_LOAD_PERCENT = 85;

        CertStore() = default;
        ~CertStore();

        CertStore(const CertStore&) = delete;
        CertStore& operator=(const CertStore&) = delete;

        /** Allocates the index and the certificate pool. capacity is the maximum
            stored certificates. InvalidParam if 0, AllocFailed if an allocation
            fails; on failure the store is left unusable, never half-built. */
        [[nodiscard]] common::Error Init(uint32_t capacity);

        /** Releases everything. Idempotent, safe on an uninitialized store.
            @warning Not safe while other threads still use the store. */
        void Shutdown();

        /** Stores a trusted certificate. Safe to call concurrently with Check and
            with other Adds (writers serialize). A tag already stored has its
            certificate replaced in place; a new tag takes a fresh slot.
            LimitReached when the store is full. */
        [[nodiscard]] common::Error Add(const Certificate& cert);

        /** Matches an announced tag against a peer's presented key. Safe under any
            concurrency with Add. A probe that keeps losing races against a mutating
            writer serializes behind the writer lock, so the result always reflects
            some instant of the store, never torn. */
        [[nodiscard]] Match Check(const Certificate::IdentityTag& tag,
                                  const common::crypto::PublicKey& presentedKey) const;

        uint32_t Count() const { return count_.load(std::memory_order_relaxed); }
        uint32_t GetCapacity() const { return capacity_; }

    private:
        /** hash and idx are relaxed atomics because readers probe them while a
            writer displaces entries; ordering comes from version_, not these. key
            is writer-only; a reader confirms a candidate against the Certificate in
            the pool, under the slot's read lock. */
        struct alignas(common::CACHE_LINE) IndexEntry
        {
            std::atomic<uint64_t>     hash{0};   ///< 0 = empty bucket
            std::atomic<uint32_t>     idx{0};    ///< slot in certPool_
            Certificate::IdentityTag  key{};     ///< writer-only; settles collisions
        };

        std::unique_ptr<IndexEntry[]> index_;
        uint32_t                      idxCapacity_ = 0;   ///< power of two
        uint32_t                      idxMask_     = 0;

        /** mutable: Check is logically const but must take slot read locks. */
        mutable common::collections::SlotPool certPool_;
        uint32_t                               capacity_ = 0;

        /** Table-wide seqlock over the index. Even = stable, odd = a writer is
            displacing entries. Monotonic so a reader can prove its probe raced
            nothing. */
        alignas(common::CACHE_LINE) std::atomic<uint32_t> version_{0};

        alignas(common::CACHE_LINE) mutable std::atomic_flag writeLock_ = ATOMIC_FLAG_INIT;
        alignas(common::CACHE_LINE) std::atomic<uint32_t>    count_{0};

        /** First 8 bytes of the tag (already uniform, tags are hashes), remapped
            away from 0, which marks an empty bucket. */
        [[nodiscard]] static uint64_t HashTag(const Certificate::IdentityTag& tag);

        void LockWriter() const noexcept;
        void UnlockWriter() const noexcept;

        /** Compares a candidate slot's certificate against tag/key under the slot's
            read lock. Sets out and returns true when the tag matches; false means a
            64-bit hash collision with a different tag. */
        [[nodiscard]] bool ResolveSlot(uint32_t slot,
                                       const Certificate::IdentityTag& tag,
                                       const common::crypto::PublicKey& presentedKey,
                                       Match& out) const;
    };
}
