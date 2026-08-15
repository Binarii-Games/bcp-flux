#pragma once

#include <cstdint>
#include <type_traits>

#include <common/platform.h>
#include <common/error.h>
#include <common/crypto/crypto.h>
#include <common/collections/slot_pool.h>

#include <flux/address.h>
#include <flux/internal/constants.h>
#include <flux/peer/peer_id.h>

namespace bcp::flux
{
    /** Fixed-capacity, allocation-free store of the resumption notes this
        socket holds, one entry per issuer identity. The issuer keeps nothing,
        so this table is the whole memory of the fast path: lose an entry and
        the next contact with that issuer costs a full handshake, never more.

        Lookups scan the pool under per-slot read locks, the same shape as the
        transfer table's directory walks. Notes are stored once per session
        and looked up once per first send to an absent peer, so this is a cold
        path and a bounded scan beats an index it would have to keep coherent.

        An entry expires by wall clock. Expiry is enforced lazily: a find
        treats an expired entry as missing and frees it, Store evicts expired
        entries before live ones when the pool is full, and the tick sweeps a
        bounded number per pass. A duplicate entry for one issuer can exist
        briefly when an import races a live receipt; the sweep collects the
        loser and finds return the first match, so the race costs memory for
        a while and correctness never. */
    class TicketTable
    {
    public:
        static constexpr uint32_t NPOS = common::collections::SlotPool::INVALID;

        /** One held note. Trivially copyable, lives in a pool slot, and the
            pool recycles bytes, so every write fills every field. `live` is
            what a scan trusts: slots the pool has never leased read false
            from the Init zeroing, and a release writes false before the slot
            returns to the free list. */
        struct Entry
        {
            bool                       live;
            BcpId                      issuerId;    ///< who sealed it, the durable key
            common::crypto::PublicKey  issuerPk;    ///< for the identity DH at resume
            Address                    addrHint;    ///< where the issuer last was
            common::crypto::SessionKey secret;      ///< holder's half, derived from the resume root
            uint64_t                   noteId;
            uint64_t                   expiryWall;  ///< WallClockSeconds past which it is dead
            uint16_t                   blobLen;
            uint8_t                    blob[internal::TICKET_BLOB_SIZE];
        };

        /** A persisted entry: magic, the fields above in explicit little-endian
            through the byte cursors, and the address hint as raw host bytes.
            The hint is machine-local by construction (it wraps the OS sockaddr),
            so a bundle moved to a foreign machine keeps everything except the
            hint, and a hint that fails to match only costs the address lookup,
            never a wrong session. */
        static constexpr size_t BUNDLE_MAX =
            4 + 32 + common::crypto::KEY_SIZE + common::crypto::KEY_SIZE
            + 8 + 8 + 2 + internal::TICKET_BLOB_SIZE + 2 + sizeof(Address);

        /** Writes entry into out, returning the bytes written, or 0 when cap
            is too small. */
        [[nodiscard]] static size_t EncodeBundle(const Entry& entry,
                                                 uint8_t* out, size_t cap);

        /** Parses a bundle into out. False on bad magic, a truncated buffer,
            or a blob longer than an entry holds; nothing else is judged here,
            because the proof happens at resume. */
        [[nodiscard]] static bool DecodeBundle(const uint8_t* bundle, size_t len,
                                               Entry& out);

        TicketTable() = default;
        ~TicketTable();

        TicketTable(const TicketTable&) = delete;
        TicketTable& operator=(const TicketTable&) = delete;

        /** Allocates the pool. InvalidParam if capacity is 0. */
        [[nodiscard]] common::Error Init(uint32_t capacity);

        /** Releases everything. Idempotent.
            @warning Not safe while other threads still use the table. */
        void Shutdown();

        /** Stores or refreshes the note from entry's issuer: an existing entry
            for that identity is overwritten in place, a new identity takes a
            free slot, and a full pool repurposes an expired entry first and
            the nearest-expiry one after that, so storing never fails for
            capacity while anything stored is worth less than the newcomer. */
        common::Error Store(const Entry& entry, uint64_t nowWall);

        /** Copies the live, unexpired entry for this issuer into out.
            NotFound otherwise. An expired entry found on the way is freed,
            which is the lazy half of cleanup. */
        [[nodiscard]] common::Error FindById(const BcpId& issuerId,
                                             uint64_t nowWall, Entry& out);

        /** Same, keyed by the address hint. */
        [[nodiscard]] common::Error FindByAddr(const Address& addr,
                                               uint64_t nowWall, Entry& out);

        /** Visits up to budget slots from a resumable cursor, freeing the
            expired entries among them, so a pass costs the same whether
            anything is dying or not. Returns how many were freed.

            @pre One sweeper at a time: the cursor is plain state, and the
                 tick that calls this is already single-pass gated. */
        uint32_t SweepExpired(uint64_t nowWall, uint32_t budget);

        uint32_t Count() const { return count_.load(std::memory_order_relaxed); }
        bool     Enabled() const { return capacity_ != 0; }

    private:
        /** Overwrites the slot under its write lock and counts it live. */
        void WriteEntry(uint32_t slot, const Entry& entry, bool wasLive);

        common::collections::SlotPool pool_;
        uint32_t                      capacity_ = 0;
        uint32_t                      sweepCursor_ = 0;   ///< tick-owned, see SweepExpired
        std::atomic<uint32_t>         count_{0};
    };

    static_assert(std::is_trivially_copyable_v<TicketTable::Entry>,
                  "Entries live in a SlotPool by raw cast");
}
