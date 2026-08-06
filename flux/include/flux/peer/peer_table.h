#pragma once

#include <array>
#include <memory>
#include <atomic>
#include <cstdint>
#include <cstddef>

#include <common/platform.h>
#include <common/error.h>
#include <common/collections/slot_pool.h>

#include <flux/address.h>
#include <flux/peer/peer.h>
#include <flux/peer/peer_id.h>
#include <flux/peer/peer_handle.h>

namespace bcp::flux
{
    /** Peers live in a SlotPool and never move; the indexes below map a key to
        a slot index. All are open-addressed with Robin Hood displacement: on
        insert, an entry that has probed further than the one in a bucket steals
        it, and the loser keeps probing. Probe lengths even out, so no peer pays
        for a collision cluster. Removal backward-shifts the run instead of
        leaving a tombstone, which keeps probe distance bounded over long uptime.

        Concurrency: many readers, rare writers. Lookup happens per packet,
        registration only on handshake.

        The address/id index pair is guarded by one table-wide seqlock
        (version_): a writer holds it odd across any mutation, and a reader
        validates its whole probe against it, retrying if the version moved.
        Per-entry versions would not be enough: displacement and backward-shift
        move entries between buckets, so a probe can miss a peer mid-move even
        when every entry it read was individually consistent.

        Readers never store to the index; a probe only loads, so entry cache
        lines stay shared and lookups scale across workers. The one store a
        successful lookup makes is taking the matched slot's read lock, where
        the key is verified against the Peer itself. Per-entry cache-line
        alignment keeps a writer's stores off neighbouring entries.

        Writers serialize on writeLock_. Displacement and backward-shift each
        move a run of entries, and a single writer makes those trivially correct
        rather than a lock-free problem with no simple answer. Writes are off
        the hot path, so serialization costs nothing that matters.

        @pre Callers must not invoke table operations while holding a PeerHandle
             from this table: writer operations wait on slot locks, and a handle
             holder calling back into the table can close a cycle between the
             two. */
    class PeerTable
    {
    public:
        static constexpr uint32_t INVALID_SLOT = common::collections::SlotPool::INVALID;

        /** Robin Hood probe length climbs sharply as a table saturates, so the
            indexes are sized past peer capacity and never exceed this load. The
            pool runs out of peers first, by design. */
        static constexpr uint32_t MAX_LOAD_PERCENT = 85;

        /** Ceiling on tag entries one peer may hold at once. The migration
            window (current tag plus the next few) never legitimately needs
            more. The tag index is sized for every peer at this ceiling. */
        static constexpr uint32_t MAX_TAGS_PER_PEER = 4;

    private:
        /** hash and idx are relaxed atomics because readers probe them while a
            writer mutates: atomicity keeps the racing loads defined, ordering
            comes from version_, not from these. key is a plain field because
            only the writer touches it. A reader confirms a candidate against
            the Peer in the pool, under the slot's read lock, so it never reads
            a 128-byte key that could be torn mid-write. */
        struct alignas(common::CACHE_LINE) AddrIndexEntry
        {
            std::atomic<uint64_t> hash{0};   ///< 0 = empty bucket; cached so a probe needs no rehash.
            std::atomic<uint32_t> idx{0};    ///< Slot index into peerPool_.
            Address               key;       ///< Writer-only; settles collisions.
        };

        struct alignas(common::CACHE_LINE) BcpIndexEntry
        {
            std::atomic<uint64_t> hash{0};
            std::atomic<uint32_t> idx{0};
            BcpId                 key;
        };

        /** The tag index shares the seqlock with the address/id indexes and is
            read the same lock-free way: GetPeersByTag probes it per migration
            event under version_, so its entries are relaxed atomics read
            concurrently with a mutating writer, each cache-line aligned so a
            writer's store never dirties a neighbour. It carries no stored key:
            the widened 4-byte tag is the hash, so hash equality is exact tag
            equality. It is multi-value on both sides, one tag mapping to several
            peers (a derived-tag clash) and one peer holding several tags (its
            migration window). */
        struct alignas(common::CACHE_LINE) TagIndexEntry
        {
            std::atomic<uint64_t> hash{0};   ///< 0 = empty bucket; else the tag.
            std::atomic<uint32_t> idx{0};    ///< Slot index into peerPool_.
        };

        std::unique_ptr<AddrIndexEntry[]> addrIdx_;
        std::unique_ptr<BcpIndexEntry[]>  bcpIdx_;
        uint32_t                          idxCapacity_ = 0;   ///< power of two
        uint32_t                          idxMask_     = 0;

        /** Sized for every peer holding MAX_TAGS_PER_PEER tags, so a bind can
            never run the index past its load cap and wedge the insert loop. */
        std::unique_ptr<TagIndexEntry[]>  tagIdx_;
        uint32_t                          tagIdxCapacity_ = 0;   ///< power of two
        uint32_t                          tagIdxMask_     = 0;
        uint32_t                          tagCapacity_    = 0;   ///< max live tag entries
        uint32_t                          tagCount_       = 0;   ///< writer-owned, under writeLock_

        common::collections::SlotPool peerPool_;
        uint32_t                      peerCapacity_ = 0;

        /** Table-wide seqlock over both indexes. Even = stable, odd = a writer
            is mutating. Monotonic so a reader can prove its probe raced nothing:
            any write cycle during the probe leaves the version different, where
            a reusable flag would read identical before and after (ABA). */
        alignas(common::CACHE_LINE) std::atomic<uint32_t> version_{0};

        alignas(common::CACHE_LINE) std::atomic_flag      writeLock_ = ATOMIC_FLAG_INIT;
        alignas(common::CACHE_LINE) std::atomic<uint32_t> peerCount_{0};

    public:
        PeerTable() = default;
        ~PeerTable();

        PeerTable(const PeerTable&) = delete;
        PeerTable& operator=(const PeerTable&) = delete;

        /** Allocates both indexes and the peer pool. `capacity` is the maximum
            live peers; the indexes are sized larger so load stays under
            MAX_LOAD_PERCENT. InvalidParam if `capacity` is 0, AllocFailed if an
            allocation fails. On failure the table is left unusable, never
            half-built. */
        [[nodiscard]] common::Error Init(uint32_t capacity);

        /** Releases everything. Idempotent, and safe on an uninitialized table. */
        void Shutdown();

        /** Inserts a peer and returns its slot in `outSlot`. `id` may be null:
            a handshake learns a peer's address before it proves an id, so a
            peer starts in the address index alone and joins the BcpId index
            later via BindId. On success the peer is findable by every key it
            was given, on failure by none of them; a partial insert is never
            observable. Registering an address that is already live returns
            AlreadyPending and inserts nothing. A full pool returns
            MaxPeersReached. */
        [[nodiscard]] common::Error RegisterPeer(const Address& addr,
                                                 const BcpId*   id,
                                                 uint32_t&      outSlot);

        /** Adds an already-registered peer to the BcpId index, for when the id
            arrives after registration. Returns AlreadyPending and changes
            nothing if the peer already carries an id; PeerNotFound if the slot
            holds no live peer. */
        [[nodiscard]] common::Error BindId(uint32_t slot, const BcpId& id);

        /** Removes a peer from every index (address, id, and all of its tags)
            and frees its slot. Index entries go first, so no new handle can
            find the peer; the slot is then write-locked, which waits until every
            outstanding PeerHandle has destructed, and only then freed. A peer is
            never freed while someone holds a handle to it. Once this returns Ok
            neither key finds the peer, and the run each key sat in is
            backward-shifted so no later lookup stops early at a hole.
            PeerNotFound if the key was never registered.

            @pre Drop any handle to this peer first. RemovePeer from a thread
                 still holding one waits on that thread's own lock, forever. */
        [[nodiscard]] common::Error RemovePeer(const Address& addr);
        [[nodiscard]] common::Error RemovePeer(const BcpId& id);

        /** Re-files a live peer under a new address, the rebind that completes
            an address migration. The peer keeps its slot, session, counters,
            replay window, id, and tags; only the address index entry moves and
            Peer.addr is rewritten. Refused with AlreadyPending if another live
            peer already holds `newAddr` (a move can never displace a peer);
            PeerNotFound if the slot holds no live peer. Rebinding to the address
            the peer already has returns Ok and changes nothing.

            During the swap a lookup by the old address may miss (the peer is
            moving, and a miss reads the same as moved), but no lookup ever
            yields a wrong or torn peer. */
        [[nodiscard]] common::Error UpdateAddress(uint32_t slot, const Address& newAddr);

        /** Indexes one more tag for a live peer. Multi-value on both sides: a
            peer holds up to MAX_TAGS_PER_PEER tags at once (its migration
            window), and two peers may share a tag (a derived-tag clash); neither
            is rejected. Callers keep their own window distinct, binding the same
            (tag, peer) pair twice makes two entries and takes two unbinds. The
            all-zero tag is reserved as the empty bucket marker and returns
            InvalidParam. PeerNotFound if the slot holds no live peer;
            LimitReached if the index is at capacity, which only happens when
            callers exceed the per-peer ceiling. */
        [[nodiscard]] common::Error BindTag(uint32_t slot, const PeerTag& tag);

        /** Removes one (tag, peer) entry; a clash-sharing peer keeps its own.
            PeerNotFound if this peer does not hold this tag. */
        [[nodiscard]] common::Error UnbindTag(uint32_t slot, const PeerTag& tag);

        /** Removes every tag the peer holds. Idempotent, Ok when it held none.
            RemovePeer does this implicitly. */
        [[nodiscard]] common::Error UnbindTags(uint32_t slot);

        /** Collects every peer bound to `tag`, usually one, occasionally more on
            a clash, and the caller disambiguates (trial decrypt picks the peer
            whose key authenticates the packet). Fills `out` with up to `max`
            read-locked handles. A lock-free seqlock reader, like GetPeer: it
            never takes the writer lock, so a migrating peer's lookup neither
            blocks registrations nor queues behind other lookups. No key is
            verified against the peer; hash equality is exact tag equality, so
            every hit is a real tag holder, and version_ validation alone guards
            against a slot recycled mid-probe.

            @return the total number bound; a value above `max` means candidates
                    were left behind rather than silently truncated. */
        [[nodiscard]] uint32_t GetPeersByTag(const PeerTag& tag, PeerHandle* out, uint32_t max);

        /** A successful handle refers to a live peer whose key matched, verified
            under the slot's read lock before returning. The index hit alone is
            not trusted, since the slot could have been recycled between reading
            the index and locking it. A hash collision never resolves to the
            wrong peer. On a miss, a failed handle carrying PeerNotFound. Probes
            retry optimistically when a mutation races them; after a bounded
            number of lost races the lookup serializes behind the writer lock, so
            progress holds even under continuous mutation. */
        [[nodiscard]] PeerHandle GetPeer(const Address& addr);
        [[nodiscard]] PeerHandle GetPeer(const BcpId& id);

        /** Copies live peers' addresses into `out` (up to `max`), resuming from
            `cursor` and advancing it. Returns the count, 0 once the sweep is
            done. Writers are held out per chunk, so each chunk is internally
            consistent, but the sweep as a whole is a best-effort snapshot: a
            peer removed after its chunk was taken fails the caller's re-lookup,
            and one registered mid-sweep waits for the next sweep. */
        [[nodiscard]] uint32_t CollectAddresses(uint32_t& cursor, Address* out, uint32_t max);

        uint32_t GetPeerCount() const { return peerCount_.load(std::memory_order_relaxed); }
        uint32_t GetCapacity()  const { return peerCapacity_; }

    private:
        /** Bucket hashes: Address::hash() for the address index; for the BcpId
            index the id's first 8 bytes, already uniform (blake2b). Remapped
            away from 0, which marks an empty bucket. The tag hash differs: the
            widened 4-byte tag verbatim, no remap (the all-zero tag is rejected
            at BindTag instead), so hash equality is exact tag equality and the
            index needs no stored key. */
        [[nodiscard]] static uint64_t HashAddr(const Address& addr);
        [[nodiscard]] static uint64_t HashId(const BcpId& id);
        [[nodiscard]] static uint64_t HashTag(const PeerTag& tag);

        /** Drops every tag entry for `slot`.

            @pre Caller holds writeLock_. */
        void ClearTagsLocked(uint32_t slot);

        void LockWriter() noexcept;
        void UnlockWriter() noexcept;

        /** Waits out every outstanding handle on the slot, then returns it to
            the pool. Unlock before release: SlotPool lock state survives
            Release. */
        void DrainAndFree(uint32_t slot);

    public:
        /** An event about this peer has been delivered. Clears Peer::emitting
            and releases the slot if a removal came and went while it was set.

            There is no matching Mark here on purpose: every site that records a
            peer event already holds that peer's write lock, so it sets the flag
            through the Peer it has rather than asking for the lock again. */
        void ClearEmitting(uint32_t slot) noexcept;

    private:
    };
}
