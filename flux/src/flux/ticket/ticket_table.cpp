#include <flux/ticket/ticket_table.h>

#include <cstring>

#include <common/wire/bytes_writer.h>
#include <common/wire/bytes_reader.h>

namespace bcp::flux
{
    static constexpr uint8_t BUNDLE_MAGIC[4] = { 'F', 'T', 'K', '1' };

    size_t TicketTable::EncodeBundle(const Entry& entry, uint8_t* out, size_t cap)
    {
        if (!out || cap < BUNDLE_MAX) return 0;

        uint16_t written = 0;
        common::BytesWriter writer{out, &written, cap};
        bool ok = writer.PutBytes(BUNDLE_MAGIC, sizeof(BUNDLE_MAGIC));
        ok = ok && writer.PutBytes(entry.issuerId.id.data(), entry.issuerId.id.size());
        ok = ok && writer.PutBytes(entry.issuerPk.data(), entry.issuerPk.size());
        ok = ok && writer.PutBytes(entry.secret.data(), entry.secret.size());
        ok = ok && writer.PutU64(entry.noteId);
        ok = ok && writer.PutU64(entry.expiryWall);
        ok = ok && writer.PutU16(entry.blobLen);
        ok = ok && writer.PutBytes(entry.blob, entry.blobLen);

        // The hint is the one field stored as raw host bytes: it wraps the OS
        // sockaddr, which has no portable layout, and it only ever has to be
        // equal to an address this same machine produces. A foreign or stale
        // hint fails the equality and costs the lookup, nothing else.
        uint8_t addrRaw[sizeof(Address)];
        std::memcpy(addrRaw, &entry.addrHint, sizeof(Address));
        ok = ok && writer.PutU16(static_cast<uint16_t>(sizeof(Address)));
        ok = ok && writer.PutBytes(addrRaw, sizeof(Address));

        return ok ? written : 0;
    }

    bool TicketTable::DecodeBundle(const uint8_t* bundle, size_t len, Entry& out)
    {
        if (!bundle) return false;

        common::BytesReader reader{bundle, len};
        uint8_t magic[4];
        if (!reader.TakeBytes(magic, sizeof(magic))) return false;
        if (std::memcmp(magic, BUNDLE_MAGIC, sizeof(magic)) != 0) return false;

        out = Entry{};
        out.live = true;
        bool ok = reader.TakeBytes(out.issuerId.id.data(), out.issuerId.id.size());
        ok = ok && reader.TakeBytes(out.issuerPk.data(), out.issuerPk.size());
        ok = ok && reader.TakeBytes(out.secret.data(), out.secret.size());
        ok = ok && reader.TakeU64(out.noteId);
        ok = ok && reader.TakeU64(out.expiryWall);
        ok = ok && reader.TakeU16(out.blobLen);
        if (!ok || out.blobLen > sizeof(out.blob)) return false;
        if (!reader.TakeBytes(out.blob, out.blobLen)) return false;

        uint16_t addrLen = 0;
        if (!reader.TakeU16(addrLen)) return false;
        if (addrLen != sizeof(Address)) return false;   // foreign layout: no hint
        uint8_t addrRaw[sizeof(Address)];
        if (!reader.TakeBytes(addrRaw, sizeof(addrRaw))) return false;
        std::memcpy(&out.addrHint, addrRaw, sizeof(Address));
        return true;
    }

    TicketTable::~TicketTable()
    {
        Shutdown();
    }

    common::Error TicketTable::Init(uint32_t capacity)
    {
        if (capacity == 0) return common::Error::InvalidParam;
        if (!pool_.Init(capacity, sizeof(Entry)))
            return common::Error::AllocFailed;
        capacity_ = capacity;
        count_.store(0, std::memory_order_relaxed);
        return common::Error::Ok;
    }

    void TicketTable::Shutdown()
    {
        pool_.Shutdown();
        capacity_ = 0;
        count_.store(0, std::memory_order_relaxed);
    }

    void TicketTable::WriteEntry(uint32_t slot, const Entry& entry, bool wasLive)
    {
        Entry* dst = reinterpret_cast<Entry*>(pool_.WriteLock(slot));
        if (dst)
        {
            *dst = entry;
            dst->live = true;
        }
        pool_.UnlockWrite(slot);
        if (!wasLive) count_.fetch_add(1, std::memory_order_relaxed);
    }

    common::Error TicketTable::Store(const Entry& entry, uint64_t nowWall)
    {
        if (capacity_ == 0) return common::Error::NotInitialized;

        // One entry per issuer: a note refreshing an identity already held
        // overwrites in place, so issuance can never grow the footprint.
        // The same walk remembers the eviction candidates in case the pool
        // is full: an expired entry first, the nearest expiry after that.
        uint32_t expiredSlot = NPOS;
        uint32_t oldestSlot  = NPOS;
        uint64_t oldestExpiry = UINT64_MAX;
        for (uint32_t slot = 0; slot < capacity_; ++slot)
        {
            const Entry* held = reinterpret_cast<const Entry*>(pool_.ReadLock(slot));
            bool match = false;
            if (held && held->live)
            {
                match = held->issuerId == entry.issuerId;
                if (held->expiryWall <= nowWall) expiredSlot = slot;
                else if (held->expiryWall < oldestExpiry)
                {
                    oldestExpiry = held->expiryWall;
                    oldestSlot   = slot;
                }
            }
            pool_.UnlockRead(slot);
            if (match)
            {
                WriteEntry(slot, entry, true);
                return common::Error::Ok;
            }
        }

        const uint32_t fresh = pool_.Acquire();
        if (fresh != NPOS)
        {
            WriteEntry(fresh, entry, false);
            return common::Error::Ok;
        }
        const uint32_t victim = expiredSlot != NPOS ? expiredSlot : oldestSlot;
        if (victim == NPOS) return common::Error::LimitReached;   // capacity 0-sized race
        WriteEntry(victim, entry, true);
        return common::Error::Ok;
    }

    common::Error TicketTable::FindById(const BcpId& issuerId,
                                        uint64_t nowWall, Entry& out)
    {
        if (capacity_ == 0) return common::Error::NotInitialized;
        for (uint32_t slot = 0; slot < capacity_; ++slot)
        {
            const Entry* held = reinterpret_cast<const Entry*>(pool_.ReadLock(slot));
            const bool match   = held && held->live && held->issuerId == issuerId;
            const bool expired = match && held->expiryWall <= nowWall;
            if (match && !expired) out = *held;
            pool_.UnlockRead(slot);

            if (expired)
            {
                // The lazy half of cleanup: found dead, freed on the spot.
                Entry* dead = reinterpret_cast<Entry*>(pool_.WriteLock(slot));
                const bool stillDead = dead && dead->live && dead->expiryWall <= nowWall
                                       && dead->issuerId == issuerId;
                if (stillDead) dead->live = false;
                pool_.UnlockWrite(slot);
                if (stillDead)
                {
                    pool_.Release(slot);
                    count_.fetch_sub(1, std::memory_order_relaxed);
                }
                continue;
            }
            if (match) return common::Error::Ok;
        }
        return common::Error::NotFound;
    }

    common::Error TicketTable::FindByAddr(const Address& addr,
                                          uint64_t nowWall, Entry& out)
    {
        if (capacity_ == 0) return common::Error::NotInitialized;
        for (uint32_t slot = 0; slot < capacity_; ++slot)
        {
            const Entry* held = reinterpret_cast<const Entry*>(pool_.ReadLock(slot));
            const bool match = held && held->live && held->expiryWall > nowWall
                               && held->addrHint == addr;
            if (match) out = *held;
            pool_.UnlockRead(slot);
            if (match) return common::Error::Ok;
        }
        return common::Error::NotFound;
    }

    uint32_t TicketTable::SweepExpired(uint64_t nowWall, uint32_t budget)
    {
        if (capacity_ == 0 || budget == 0) return 0;
        if (budget > capacity_) budget = capacity_;

        uint32_t freed = 0;
        for (uint32_t visited = 0; visited < budget; ++visited)
        {
            const uint32_t slot = sweepCursor_;
            sweepCursor_ = (sweepCursor_ + 1) % capacity_;

            // Read first, upgrade only on a hit, so a pass over a healthy
            // table costs read locks alone.
            const Entry* held = reinterpret_cast<const Entry*>(pool_.ReadLock(slot));
            const bool expired = held && held->live && held->expiryWall <= nowWall;
            pool_.UnlockRead(slot);
            if (!expired) continue;

            Entry* dead = reinterpret_cast<Entry*>(pool_.WriteLock(slot));
            const bool stillDead = dead && dead->live && dead->expiryWall <= nowWall;
            if (stillDead) dead->live = false;
            pool_.UnlockWrite(slot);
            if (stillDead)
            {
                pool_.Release(slot);
                count_.fetch_sub(1, std::memory_order_relaxed);
                ++freed;
            }
        }
        return freed;
    }
}
