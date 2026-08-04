#include <flux/peer/peer_table.h>

#include <atomic>
#include <cassert>
#include <cstring>
#include <new>

#include <common/math.h>
#include <common/platform.h>

namespace bcp::flux
{
    namespace
    {
        constexpr uint32_t NPOS = UINT32_MAX;

        /** Optimistic probes a lookup makes before it serializes behind the
            writer lock. Retries happen only when a mutation raced the probe,
            leaving the slow path idle at sane write rates. It caps how long a
            continuously-mutating writer can delay a reader, not starve it. */
        constexpr uint32_t MAX_OPTIMISTIC_ATTEMPTS = 16;

        uint32_t Dist(uint64_t hash, uint32_t pos, uint32_t mask)
        {
            return (pos - (static_cast<uint32_t>(hash) & mask)) & mask;
        }

        /** Writer-side probe.

            @pre Caller holds writeLock_, so key reads are plain and no version
                 dance is needed. */
        template<typename Entry, typename Eq>
        uint32_t FindPos(const Entry* entries, uint32_t mask, uint64_t hash, Eq&& eq)
        {
            uint32_t pos = static_cast<uint32_t>(hash) & mask;
            for (uint32_t dist = 0; ; ++dist)
            {
                const uint64_t entryHash = entries[pos].hash.load(std::memory_order_relaxed);
                if (entryHash == 0)
                    return NPOS;
                if (entryHash == hash && eq(entries[pos]))
                    return pos;
                if (Dist(entryHash, pos, mask) < dist)
                    return NPOS;
                pos = (pos + 1) & mask;
            }
        }

        /** Robin Hood insert. An entry that has probed further than the one
            occupying a bucket steals it, and the loser carries on. The load
            cap guarantees termination: a table under MAX_LOAD_PERCENT always
            has an empty slot ahead.

            @pre Caller holds writeLock_ and version_ is odd. */
        template<typename Entry, typename Key>
        void InsertEntry(Entry* entries, uint32_t mask, uint64_t hash, uint32_t slot, const Key& key)
        {
            uint64_t carryHash = hash;
            uint32_t carrySlot = slot;
            Key      carryKey  = key;

            uint32_t pos  = static_cast<uint32_t>(carryHash) & mask;
            uint32_t dist = 0;
            for (;;)
            {
                Entry& entry = entries[pos];
                const uint64_t entryHash = entry.hash.load(std::memory_order_relaxed);
                if (entryHash == 0)
                {
                    entry.idx.store(carrySlot, std::memory_order_relaxed);
                    entry.key = carryKey;
                    entry.hash.store(carryHash, std::memory_order_relaxed);
                    return;
                }

                const uint32_t entryDist = Dist(entryHash, pos, mask);
                if (entryDist < dist)
                {
                    const uint32_t evictedSlot = entry.idx.load(std::memory_order_relaxed);
                    const Key      evictedKey  = entry.key;
                    entry.idx.store(carrySlot, std::memory_order_relaxed);
                    entry.key = carryKey;
                    entry.hash.store(carryHash, std::memory_order_relaxed);
                    carryHash = entryHash;
                    carrySlot = evictedSlot;
                    carryKey  = evictedKey;
                    dist = entryDist;
                }

                pos = (pos + 1) & mask;
                ++dist;
            }
        }

        /** Backward-shift removal. The run after the hole moves one step left
            until an empty bucket or an entry already on its ideal bucket, so no
            probe ever stops early at a tombstone.

            @pre Caller holds writeLock_ and version_ is odd. */
        template<typename Entry>
        void RemoveEntryAt(Entry* entries, uint32_t mask, uint32_t pos)
        {
            for (;;)
            {
                const uint32_t next = (pos + 1) & mask;
                Entry& nextEntry = entries[next];
                const uint64_t nextHash = nextEntry.hash.load(std::memory_order_relaxed);
                if (nextHash == 0 || Dist(nextHash, next, mask) == 0)
                {
                    entries[pos].hash.store(0, std::memory_order_relaxed);
                    return;
                }
                entries[pos].idx.store(nextEntry.idx.load(std::memory_order_relaxed), std::memory_order_relaxed);
                entries[pos].key = nextEntry.key;
                entries[pos].hash.store(nextHash, std::memory_order_relaxed);
                pos = next;
            }
        }

        // Tag-index siblings of FindPos / InsertEntry / RemoveEntryAt. Same
        // Robin Hood mechanics and relaxed-atomic access, since a GetPeersByTag
        // reader probes these entries concurrently under version_ and plain
        // fields would race. No key to carry or compare here: the hash is the
        // tag, so hash equality settles identity.

        /** Locates the one entry matching both the tag and the slot. A tag may
            be shared by several peers, so the pair is the identity.

            @pre Caller holds writeLock_, so relaxed loads are exact. */
        template<typename Entry>
        uint32_t FindTagPos(const Entry* entries, uint32_t mask, uint64_t hash, uint32_t slot)
        {
            uint32_t pos = static_cast<uint32_t>(hash) & mask;
            for (uint32_t dist = 0; ; ++dist)
            {
                const uint64_t entryHash = entries[pos].hash.load(std::memory_order_relaxed);
                if (entryHash == 0)
                    return NPOS;
                if (entryHash == hash && entries[pos].idx.load(std::memory_order_relaxed) == slot)
                    return pos;
                if (Dist(entryHash, pos, mask) < dist)
                    return NPOS;
                pos = (pos + 1) & mask;
            }
        }

        template<typename Entry>
        void InsertTagEntry(Entry* entries, uint32_t mask, uint64_t hash, uint32_t slot)
        {
            uint64_t carryHash = hash;
            uint32_t carrySlot = slot;

            uint32_t pos  = static_cast<uint32_t>(carryHash) & mask;
            uint32_t dist = 0;
            for (;;)
            {
                Entry& entry = entries[pos];
                const uint64_t entryHash = entry.hash.load(std::memory_order_relaxed);
                if (entryHash == 0)
                {
                    entry.idx.store(carrySlot, std::memory_order_relaxed);
                    entry.hash.store(carryHash, std::memory_order_relaxed);
                    return;
                }

                const uint32_t entryDist = Dist(entryHash, pos, mask);
                if (entryDist < dist)
                {
                    const uint32_t evictedSlot = entry.idx.load(std::memory_order_relaxed);
                    entry.idx.store(carrySlot, std::memory_order_relaxed);
                    entry.hash.store(carryHash, std::memory_order_relaxed);
                    carryHash = entryHash;
                    carrySlot = evictedSlot;
                    dist = entryDist;
                }

                pos = (pos + 1) & mask;
                ++dist;
            }
        }

        template<typename Entry>
        void RemoveTagEntryAt(Entry* entries, uint32_t mask, uint32_t pos)
        {
            for (;;)
            {
                const uint32_t next = (pos + 1) & mask;
                Entry& nextEntry = entries[next];
                const uint64_t nextHash = nextEntry.hash.load(std::memory_order_relaxed);
                if (nextHash == 0 || Dist(nextHash, next, mask) == 0)
                {
                    entries[pos].hash.store(0, std::memory_order_relaxed);
                    return;
                }
                entries[pos].idx.store(nextEntry.idx.load(std::memory_order_relaxed), std::memory_order_relaxed);
                entries[pos].hash.store(nextHash, std::memory_order_relaxed);
                pos = next;
            }
        }

        /** Seqlock-validated lookup. Loads version_ (even or spin), probes with
            relaxed loads, and accepts the result only if version_ is unchanged
            afterward, else it retries a probe that may have raced a
            displacement. A candidate's key is verified against the Peer under
            the slot's read lock, which also pins the slot, so a returned handle
            can never point into memory RemovePeer has freed.

            Retries are bounded. A lookup that keeps losing races against a
            continuously-mutating writer falls back to taking writeLock itself,
            where the probe cannot race, giving guaranteed reader progress
            rather than probabilistic. */
        template<typename Entry, typename Verify>
        PeerHandle Lookup(const Entry* entries, uint32_t mask, uint32_t capacity,
                          const std::atomic<uint32_t>& version,
                          std::atomic_flag& writeLock,
                          common::collections::SlotPool& pool,
                          uint64_t hash, Verify&& verify)
        {
            for (uint32_t attempt = 0; attempt < MAX_OPTIMISTIC_ATTEMPTS; ++attempt)
            {
                const uint32_t startVersion = version.load(std::memory_order_acquire);
                if (startVersion & 1u)
                {
                    common::CpuPause();
                    continue;
                }

                bool retry = false;
                uint32_t pos = static_cast<uint32_t>(hash) & mask;
                for (uint32_t dist = 0; dist < capacity; ++dist)
                {
                    const Entry& entry = entries[pos];
                    const uint64_t entryHash = entry.hash.load(std::memory_order_relaxed);
                    if (entryHash == 0)
                        break;

                    if (entryHash == hash)
                    {
                        const uint32_t slot = entry.idx.load(std::memory_order_relaxed);
                        const Peer* peer = reinterpret_cast<const Peer*>(pool.ReadLock(slot));
                        if (verify(*peer))
                        {
                            std::atomic_thread_fence(std::memory_order_acquire);
                            if (version.load(std::memory_order_relaxed) == startVersion)
                                return PeerHandle{slot, &pool, peer};

                            // The index moved while we probed; the slot may
                            // have been recycled under a matching key. Retry.
                            pool.UnlockRead(slot);
                            retry = true;
                            break;
                        }
                        // Same 64-bit hash, different key: keep probing.
                        pool.UnlockRead(slot);
                    }
                    else if (Dist(entryHash, pos, mask) < dist)
                    {
                        break;
                    }

                    pos = (pos + 1) & mask;
                }
                if (retry)
                    continue;

                std::atomic_thread_fence(std::memory_order_acquire);
                if (version.load(std::memory_order_relaxed) == startVersion)
                    return PeerHandle{common::Error::NotFound};
            }

            // Slow path: probe under the writer lock. Acquiring it excludes
            // every mutation, so no version dance is needed; the slot's read
            // lock is still taken before the lock drops, keeping the handle
            // drain-safe once writers resume.
            while (writeLock.test_and_set(std::memory_order_acquire))
                common::CpuPause();

            PeerHandle result{common::Error::NotFound};
            uint32_t pos = static_cast<uint32_t>(hash) & mask;
            for (uint32_t dist = 0; dist < capacity; ++dist)
            {
                const Entry& entry = entries[pos];
                const uint64_t entryHash = entry.hash.load(std::memory_order_relaxed);
                if (entryHash == 0)
                    break;

                if (entryHash == hash)
                {
                    const uint32_t slot = entry.idx.load(std::memory_order_relaxed);
                    const Peer* peer = reinterpret_cast<const Peer*>(pool.ReadLock(slot));
                    if (verify(*peer))
                    {
                        result = PeerHandle{slot, &pool, peer};
                        break;
                    }
                    pool.UnlockRead(slot);
                }
                else if (Dist(entryHash, pos, mask) < dist)
                {
                    break;
                }

                pos = (pos + 1) & mask;
            }

            writeLock.clear(std::memory_order_release);
            return result;
        }
    }

    PeerTable::~PeerTable()
    {
        Shutdown();
    }

    common::Error PeerTable::Init(uint32_t capacity)
    {
        if (capacity == 0)
            return common::Error::InvalidParam;

        const uint64_t need = (static_cast<uint64_t>(capacity) * 100 + MAX_LOAD_PERCENT - 1) / MAX_LOAD_PERCENT;
        if (need > (1u << 30))
            return common::Error::InvalidParam;

        // The tag index carries up to MAX_TAGS_PER_PEER entries per peer, so it
        // is sized on its own: at the shared size, full occupancy would push it
        // past the load cap and a Robin Hood insert could never find an empty
        // bucket.
        const uint64_t tagCapacity = static_cast<uint64_t>(capacity) * MAX_TAGS_PER_PEER;
        const uint64_t tagNeed     = (tagCapacity * 100 + MAX_LOAD_PERCENT - 1) / MAX_LOAD_PERCENT;
        if (tagNeed > (1u << 30))
            return common::Error::InvalidParam;

        idxCapacity_    = common::NextPowerOfTwo(static_cast<uint32_t>(need));
        idxMask_        = idxCapacity_ - 1;
        tagIdxCapacity_ = common::NextPowerOfTwo(static_cast<uint32_t>(tagNeed));
        tagIdxMask_     = tagIdxCapacity_ - 1;
        tagCapacity_    = static_cast<uint32_t>(tagCapacity);

        addrIdx_.reset(new (std::nothrow) AddrIndexEntry[idxCapacity_]);
        bcpIdx_.reset(new (std::nothrow) BcpIndexEntry[idxCapacity_]);
        tagIdx_.reset(new (std::nothrow) TagIndexEntry[tagIdxCapacity_]);
        if (!addrIdx_ || !bcpIdx_ || !tagIdx_)
        {
            Shutdown();
            return common::Error::AllocFailed;
        }

        const uint32_t stride = static_cast<uint32_t>(
            (sizeof(Peer) + common::CACHE_LINE - 1) & ~(common::CACHE_LINE - 1));
        if (!peerPool_.Init(capacity, stride))
        {
            Shutdown();
            return common::Error::AllocFailed;
        }

        peerCapacity_ = capacity;
        version_.store(0, std::memory_order_relaxed);
        peerCount_.store(0, std::memory_order_relaxed);
        return common::Error::Ok;
    }

    void PeerTable::Shutdown()
    {
        addrIdx_.reset();
        bcpIdx_.reset();
        tagIdx_.reset();
        peerPool_.Shutdown();
        idxCapacity_    = 0;
        idxMask_        = 0;
        tagIdxCapacity_ = 0;
        tagIdxMask_     = 0;
        tagCapacity_    = 0;
        tagCount_       = 0;
        peerCapacity_   = 0;
        version_.store(0, std::memory_order_relaxed);
        peerCount_.store(0, std::memory_order_relaxed);
    }

    common::Error PeerTable::RegisterPeer(const Address& addr, const BcpId* id, uint32_t& outSlot)
    {
        outSlot = INVALID_SLOT;
        if (!addrIdx_)
            return common::Error::NotInitialized;
        if (!addr.IsSet())
            return common::Error::InvalidParam;

        const uint64_t ah = HashAddr(addr);

        LockWriter();

        if (peerCount_.load(std::memory_order_relaxed) >= peerCapacity_)
        {
            UnlockWriter();
            return common::Error::LimitReached;
        }

        if (FindPos(addrIdx_.get(), idxMask_, ah,
                    [&](const AddrIndexEntry& e) { return e.key == addr; }) != NPOS)
        {
            UnlockWriter();
            return common::Error::AlreadyPending;
        }

        uint64_t ih = 0;
        if (id)
        {
            ih = HashId(*id);
            if (FindPos(bcpIdx_.get(), idxMask_, ih,
                        [&](const BcpIndexEntry& e) { return e.key == *id; }) != NPOS)
            {
                UnlockWriter();
                return common::Error::AlreadyPending;
            }
        }

        const uint32_t slot = peerPool_.Acquire();
        if (slot == INVALID_SLOT)
        {
            UnlockWriter();
            return common::Error::LimitReached;
        }

        // A recycled slot holds the previous peer's bytes; write every field.
        // The peer is born unproven with no pending packets. The socket
        // promotes it through the handshake states via a handle.
        Peer* p = reinterpret_cast<Peer*>(peerPool_.WriteLock(slot));
        p->addr        = addr;
        p->id          = id ? *id : BcpId{};
        p->theirPk     = {};
        p->session     = {};
        p->headerKey   = {};
        p->macKey      = {};
        p->sendCounter = 0;
        p->myTagStep    = 0;
        p->theirTagStep = 0;
        p->myTag        = PeerTag{};
        p->pathAddr     = Address{};
        std::memset(p->pathChallenge, 0, sizeof(p->pathChallenge));
        p->pathStep     = 0;
        std::memset(p->hsSalt, 0, sizeof(p->hsSalt));
        std::memset(p->announcedTag, 0, sizeof(p->announcedTag));
        p->hsEphSecret = {};
        p->hsPeerEph   = {};
        p->hsEphPub    = {};
        std::memset(p->hsConfirm, 0, sizeof(p->hsConfirm));
        p->pendingHead = common::collections::SlotPool::INVALID;
        p->pendingTail = common::collections::SlotPool::INVALID;
        p->firstSeenAt = SeenStamp(common::MonotonicMicros());
        p->lastSeenAt  = p->firstSeenAt;
        p->congestionBudget     = internal::CC_INITIAL_WINDOW_BYTES;
        p->bytesInFlight        = 0;
        // Both generations restart with the slot. Inheriting a high one from a
        // previous occupant would make every grant the new peer sends look
        // older than what is already applied, and nothing would ever take.
        p->theirGrant           = 0;   // no limit named yet
        p->outstandingToPeer    = 0;
        p->theirGrantGeneration = 0;
        p->ourGrantGeneration   = 0;
        p->grantSendPending     = false;   // raised when a session commits
        p->grantSentAtMicros    = 0;
        p->slowStartThreshold   = UINT32_MAX;   // pure fast-ramp until the first loss
        p->pathSrttMicros       = 0;
        p->lastLossReactionMicros = 0;
        p->state       = HandshakeState::AWAITING_CHALLENGE;
        p->attempts    = 0;
        p->hasId       = (id != nullptr);
        p->authenticated = false;
        p->confirmed     = false;
        peerPool_.UnlockWrite(slot);

        const uint32_t v = version_.load(std::memory_order_relaxed);
        version_.store(v + 1, std::memory_order_relaxed);
        std::atomic_thread_fence(std::memory_order_release);
        InsertEntry(addrIdx_.get(), idxMask_, ah, slot, addr);
        if (id)
            InsertEntry(bcpIdx_.get(), idxMask_, ih, slot, *id);
        version_.store(v + 2, std::memory_order_release);

        peerCount_.fetch_add(1, std::memory_order_relaxed);
        UnlockWriter();

        outSlot = slot;
        return common::Error::Ok;
    }

    common::Error PeerTable::BindId(uint32_t slot, const BcpId& id)
    {
        if (!addrIdx_)
            return common::Error::NotInitialized;
        if (slot >= peerPool_.GetCapacity())
            return common::Error::InvalidParam;

        const uint64_t ih = HashId(id);

        LockWriter();

        // The slot's liveness is proven through the address index: a live peer
        // is always reachable by its address, and a freed or recycled slot no
        // longer maps back to itself.
        Peer* p = reinterpret_cast<Peer*>(peerPool_.WriteLock(slot));
        const uint32_t apos = FindPos(addrIdx_.get(), idxMask_, HashAddr(p->addr),
                                      [&](const AddrIndexEntry& e) { return e.key == p->addr; });
        if (apos == NPOS || addrIdx_[apos].idx.load(std::memory_order_relaxed) != slot)
        {
            peerPool_.UnlockWrite(slot);
            UnlockWriter();
            return common::Error::NotFound;
        }

        if (p->hasId)
        {
            peerPool_.UnlockWrite(slot);
            UnlockWriter();
            return common::Error::AlreadyPending;
        }

        if (FindPos(bcpIdx_.get(), idxMask_, ih,
                    [&](const BcpIndexEntry& e) { return e.key == id; }) != NPOS)
        {
            peerPool_.UnlockWrite(slot);
            UnlockWriter();
            return common::Error::AlreadyPending;
        }

        p->id    = id;
        p->hasId = true;

        const uint32_t v = version_.load(std::memory_order_relaxed);
        version_.store(v + 1, std::memory_order_relaxed);
        std::atomic_thread_fence(std::memory_order_release);
        InsertEntry(bcpIdx_.get(), idxMask_, ih, slot, id);
        version_.store(v + 2, std::memory_order_release);

        peerPool_.UnlockWrite(slot);
        UnlockWriter();
        return common::Error::Ok;
    }

    common::Error PeerTable::RemovePeer(const Address& addr)
    {
        if (!addrIdx_)
            return common::Error::NotInitialized;

        const uint64_t ah = HashAddr(addr);

        LockWriter();

        const uint32_t apos = FindPos(addrIdx_.get(), idxMask_, ah,
                                      [&](const AddrIndexEntry& e) { return e.key == addr; });
        if (apos == NPOS)
        {
            UnlockWriter();
            return common::Error::NotFound;
        }
        const uint32_t slot = addrIdx_[apos].idx.load(std::memory_order_relaxed);

        // The id lives on the peer; read it under the slot's read lock, since
        // a handle holder may be writing the peer at the same time.
        const Peer* pr = reinterpret_cast<const Peer*>(peerPool_.ReadLock(slot));
        const bool  hasId = pr->hasId;
        const BcpId pid   = pr->id;
        peerPool_.UnlockRead(slot);

        uint32_t bpos = NPOS;
        if (hasId)
        {
            bpos = FindPos(bcpIdx_.get(), idxMask_, HashId(pid),
                           [&](const BcpIndexEntry& e) { return e.key == pid; });
            assert(bpos != NPOS);
        }

        const uint32_t v = version_.load(std::memory_order_relaxed);
        version_.store(v + 1, std::memory_order_relaxed);
        std::atomic_thread_fence(std::memory_order_release);
        RemoveEntryAt(addrIdx_.get(), idxMask_, apos);
        if (bpos != NPOS)
            RemoveEntryAt(bcpIdx_.get(), idxMask_, bpos);
        ClearTagsLocked(slot);
        version_.store(v + 2, std::memory_order_release);

        peerCount_.fetch_sub(1, std::memory_order_relaxed);
        UnlockWriter();

        DrainAndFree(slot);
        return common::Error::Ok;
    }

    common::Error PeerTable::RemovePeer(const BcpId& id)
    {
        if (!addrIdx_)
            return common::Error::NotInitialized;

        const uint64_t ih = HashId(id);

        LockWriter();

        const uint32_t bpos = FindPos(bcpIdx_.get(), idxMask_, ih,
                                      [&](const BcpIndexEntry& e) { return e.key == id; });
        if (bpos == NPOS)
        {
            UnlockWriter();
            return common::Error::NotFound;
        }
        const uint32_t slot = bcpIdx_[bpos].idx.load(std::memory_order_relaxed);

        const Peer* pr = reinterpret_cast<const Peer*>(peerPool_.ReadLock(slot));
        const Address paddr = pr->addr;
        peerPool_.UnlockRead(slot);

        const uint32_t apos = FindPos(addrIdx_.get(), idxMask_, HashAddr(paddr),
                                      [&](const AddrIndexEntry& e) { return e.key == paddr; });
        assert(apos != NPOS);

        const uint32_t v = version_.load(std::memory_order_relaxed);
        version_.store(v + 1, std::memory_order_relaxed);
        std::atomic_thread_fence(std::memory_order_release);
        if (apos != NPOS)
            RemoveEntryAt(addrIdx_.get(), idxMask_, apos);
        RemoveEntryAt(bcpIdx_.get(), idxMask_, bpos);
        ClearTagsLocked(slot);
        version_.store(v + 2, std::memory_order_release);

        peerCount_.fetch_sub(1, std::memory_order_relaxed);
        UnlockWriter();

        DrainAndFree(slot);
        return common::Error::Ok;
    }

    common::Error PeerTable::UpdateAddress(uint32_t slot, const Address& newAddr)
    {
        if (!addrIdx_)
            return common::Error::NotInitialized;
        if (slot >= peerPool_.GetCapacity() || !newAddr.IsSet())
            return common::Error::InvalidParam;

        const uint64_t nh = HashAddr(newAddr);

        LockWriter();

        // The slot's liveness is proven through the address index, as in
        // BindId: a live peer always maps back to its own slot.
        const Peer* pr = reinterpret_cast<const Peer*>(peerPool_.ReadLock(slot));
        const Address oldAddr = pr->addr;
        peerPool_.UnlockRead(slot);

        const uint64_t oh = HashAddr(oldAddr);
        const uint32_t apos = FindPos(addrIdx_.get(), idxMask_, oh,
                                      [&](const AddrIndexEntry& e) { return e.key == oldAddr; });
        if (apos == NPOS || addrIdx_[apos].idx.load(std::memory_order_relaxed) != slot)
        {
            UnlockWriter();
            return common::Error::NotFound;
        }

        if (newAddr == oldAddr)
        {
            UnlockWriter();
            return common::Error::Ok;
        }

        // A move never displaces a live peer already holding the address.
        if (FindPos(addrIdx_.get(), idxMask_, nh,
                    [&](const AddrIndexEntry& e) { return e.key == newAddr; }) != NPOS)
        {
            UnlockWriter();
            return common::Error::AlreadyPending;
        }

        // Peer.addr is rewritten before the index swap, like BindId's field
        // writes: a reader that races the swap either retries on the version
        // bump or fails the key verify and reads a miss, never a wrong peer.
        Peer* pw = reinterpret_cast<Peer*>(peerPool_.WriteLock(slot));
        pw->addr = newAddr;
        peerPool_.UnlockWrite(slot);

        const uint32_t v = version_.load(std::memory_order_relaxed);
        version_.store(v + 1, std::memory_order_relaxed);
        std::atomic_thread_fence(std::memory_order_release);
        RemoveEntryAt(addrIdx_.get(), idxMask_, apos);
        InsertEntry(addrIdx_.get(), idxMask_, nh, slot, newAddr);
        version_.store(v + 2, std::memory_order_release);

        UnlockWriter();
        return common::Error::Ok;
    }

    common::Error PeerTable::BindTag(uint32_t slot, const PeerTag& tag)
    {
        if (!addrIdx_)
            return common::Error::NotInitialized;
        if (slot >= peerPool_.GetCapacity())
            return common::Error::InvalidParam;

        const uint64_t th = HashTag(tag);
        if (th == 0)
            return common::Error::InvalidParam;

        LockWriter();

        if (tagCount_ >= tagCapacity_)
        {
            UnlockWriter();
            return common::Error::LimitReached;
        }

        // The slot's liveness is proven through the address index, as in
        // BindId: a live peer always maps back to its own slot, a freed or
        // recycled one does not.
        const Peer* p = reinterpret_cast<const Peer*>(peerPool_.ReadLock(slot));
        const Address addr = p->addr;
        peerPool_.UnlockRead(slot);

        const uint32_t apos = FindPos(addrIdx_.get(), idxMask_, HashAddr(addr),
                                      [&](const AddrIndexEntry& e) { return e.key == addr; });
        
        if (apos == NPOS || addrIdx_[apos].idx.load(std::memory_order_relaxed) != slot)
        {
            UnlockWriter();
            return common::Error::NotFound;
        }

        const uint32_t v = version_.load(std::memory_order_relaxed);
        version_.store(v + 1, std::memory_order_relaxed);
        std::atomic_thread_fence(std::memory_order_release);
        InsertTagEntry(tagIdx_.get(), tagIdxMask_, th, slot);
        version_.store(v + 2, std::memory_order_release);
        ++tagCount_;

        UnlockWriter();
        return common::Error::Ok;
    }

    common::Error PeerTable::UnbindTag(uint32_t slot, const PeerTag& tag)
    {
        if (!addrIdx_)
            return common::Error::NotInitialized;

        const uint64_t th = HashTag(tag);
        if (th == 0)
            return common::Error::InvalidParam;

        LockWriter();

        const uint32_t tpos = FindTagPos(tagIdx_.get(), tagIdxMask_, th, slot);
        if (tpos == NPOS)
        {
            UnlockWriter();
            return common::Error::NotFound;
        }

        const uint32_t v = version_.load(std::memory_order_relaxed);
        version_.store(v + 1, std::memory_order_relaxed);
        std::atomic_thread_fence(std::memory_order_release);
        RemoveTagEntryAt(tagIdx_.get(), tagIdxMask_, tpos);
        version_.store(v + 2, std::memory_order_release);
        --tagCount_;

        UnlockWriter();
        return common::Error::Ok;
    }

    common::Error PeerTable::UnbindTags(uint32_t slot)
    {
        if (!addrIdx_)
            return common::Error::NotInitialized;

        LockWriter();
        const uint32_t v = version_.load(std::memory_order_relaxed);
        version_.store(v + 1, std::memory_order_relaxed);
        std::atomic_thread_fence(std::memory_order_release);
        ClearTagsLocked(slot);
        version_.store(v + 2, std::memory_order_release);
        UnlockWriter();
        return common::Error::Ok;
    }

    uint32_t PeerTable::GetPeersByTag(const PeerTag& tag, PeerHandle* out, uint32_t max)
    {
        if (!addrIdx_ || !out || max == 0)
            return 0;

        const uint64_t th = HashTag(tag);
        if (th == 0)
            return 0;

        // Seqlock reader, same shape as Lookup, collecting every match instead
        // of the first. Candidates are pinned under their read locks as found,
        // then the whole probe is validated against version_: if a mutation
        // raced, every pin is dropped and the probe retries, so a returned
        // handle never comes from a probe that saw a displacement or a slot
        // recycled mid-walk. No key is verified against the peer: hash equality
        // is tag equality (a hit is always a real tag holder), and a genuine
        // clash is disambiguated above the table by trial decrypt.
        for (uint32_t attempt = 0; attempt < MAX_OPTIMISTIC_ATTEMPTS; ++attempt)
        {
            const uint32_t v1 = version_.load(std::memory_order_acquire);
            if (v1 & 1u)
            {
                common::CpuPause();
                continue;
            }

            uint32_t found  = 0;   // total tag holders seen (may exceed max)
            uint32_t pinned = 0;   // handles actually taken (<= max)
            uint32_t pos = static_cast<uint32_t>(th) & tagIdxMask_;
            for (uint32_t dist = 0; dist < tagIdxCapacity_; ++dist)
            {
                const uint64_t entryHash = tagIdx_[pos].hash.load(std::memory_order_relaxed);
                if (entryHash == 0)
                    break;

                if (entryHash == th)
                {
                    if (found < max)
                    {
                        const uint32_t idx = tagIdx_[pos].idx.load(std::memory_order_relaxed);
                        const Peer* peer = reinterpret_cast<const Peer*>(peerPool_.ReadLock(idx));
                        out[pinned++] = PeerHandle{idx, &peerPool_, peer};
                    }
                    ++found;
                }
                else if (Dist(entryHash, pos, tagIdxMask_) < dist)
                {
                    break;
                }

                pos = (pos + 1) & tagIdxMask_;
            }

            std::atomic_thread_fence(std::memory_order_acquire);
            if (version_.load(std::memory_order_relaxed) == v1)
                return found;

            // The index moved while we probed; drop every pin and retry.
            for (uint32_t i = 0; i < pinned; ++i)
                out[i] = PeerHandle{common::Error::NotFound};
        }

        // Slow path: probe under the writer lock, where the index is frozen
        // and no version dance is needed; pins are still taken before the lock
        // drops, so the handles stay drain-safe once writers resume.
        LockWriter();
        uint32_t found  = 0;
        uint32_t pinned = 0;
        uint32_t pos = static_cast<uint32_t>(th) & tagIdxMask_;
        for (uint32_t dist = 0; dist < tagIdxCapacity_; ++dist)
        {
            const uint64_t entryHash = tagIdx_[pos].hash.load(std::memory_order_relaxed);
            if (entryHash == 0)
                break;

            if (entryHash == th)
            {
                if (found < max)
                {
                    const uint32_t idx = tagIdx_[pos].idx.load(std::memory_order_relaxed);
                    const Peer* peer = reinterpret_cast<const Peer*>(peerPool_.ReadLock(idx));
                    out[pinned++] = PeerHandle{idx, &peerPool_, peer};
                }
                ++found;
            }
            else if (Dist(entryHash, pos, tagIdxMask_) < dist)
            {
                break;
            }

            pos = (pos + 1) & tagIdxMask_;
        }
        UnlockWriter();
        return found;
    }

    PeerHandle PeerTable::GetPeer(const Address& addr)
    {
        if (!addrIdx_)
            return PeerHandle{common::Error::NotInitialized};

        return Lookup(addrIdx_.get(), idxMask_, idxCapacity_, version_, writeLock_, peerPool_,
                      HashAddr(addr),
                      [&](const Peer& p) { return p.addr == addr; });
    }

    PeerHandle PeerTable::GetPeer(const BcpId& id)
    {
        if (!addrIdx_)
            return PeerHandle{common::Error::NotInitialized};

        return Lookup(bcpIdx_.get(), idxMask_, idxCapacity_, version_, writeLock_, peerPool_,
                      HashId(id),
                      [&](const Peer& p) { return p.hasId && p.id == id; });
    }

    uint32_t PeerTable::CollectAddresses(uint32_t& cursor, Address* out, uint32_t max)
    {
        if (!addrIdx_ || max == 0)
            return 0;

        LockWriter();

        // Under writeLock_ the entry keys are writer-owned state, so plain
        // reads are exact: no seqlock dance and no slot locks needed here.
        uint32_t n   = 0;
        uint32_t pos = cursor;
        for (; pos < idxCapacity_ && n < max; ++pos)
        {
            if (addrIdx_[pos].hash.load(std::memory_order_relaxed) == 0)
                continue;
            out[n++] = addrIdx_[pos].key;
        }
        cursor = pos;

        UnlockWriter();
        return n;
    }

    uint64_t PeerTable::HashAddr(const Address& addr)
    {
        const uint64_t h = static_cast<uint64_t>(addr.hash());
        return h ? h : 1;
    }

    uint64_t PeerTable::HashId(const BcpId& id)
    {
        uint64_t h;
        std::memcpy(&h, id.id.data(), sizeof(h));
        return h ? h : 1;
    }

    uint64_t PeerTable::HashTag(const PeerTag& tag)
    {
        // Widened verbatim, low half only: no remap away from 0, so hash
        // equality stays tag equality; BindTag rejects the reserved all-zero
        // tag instead. Host byte order is fine: the value never leaves the
        // process and is recomputed from the tag on every use.
        uint64_t h = 0;
        std::memcpy(&h, tag.data(), tag.size());
        return h;
    }

    void PeerTable::LockWriter() noexcept
    {
        while (writeLock_.test_and_set(std::memory_order_acquire))
            common::CpuPause();
    }

    void PeerTable::UnlockWriter() noexcept
    {
        writeLock_.clear(std::memory_order_release);
    }

    void PeerTable::ClearTagsLocked(uint32_t slot)
    {
        if (!tagIdx_)
            return;

        // Caller holds writeLock_ and owns the version_ bracket around this;
        // the whole clear publishes as one seqlock step.
        for (uint32_t pos = 0; pos < tagIdxCapacity_; ++pos)
        {
            // Backward-shift removal pulls the next run entry into this
            // bucket, so re-check in place before moving on, else a shifted-in
            // match would be skipped.
            while (tagIdx_[pos].hash.load(std::memory_order_relaxed) != 0 &&
                   tagIdx_[pos].idx.load(std::memory_order_relaxed) == slot)
            {
                RemoveTagEntryAt(tagIdx_.get(), tagIdxMask_, pos);
                --tagCount_;
            }
        }
    }

    void PeerTable::DrainAndFree(uint32_t slot)
    {
        // No index entry references the slot anymore, so no new handle can be
        // minted for it; the write lock waits out the handles that still exist.
        peerPool_.WriteLock(slot);
        peerPool_.UnlockWrite(slot);
        peerPool_.Release(slot);
    }
}
