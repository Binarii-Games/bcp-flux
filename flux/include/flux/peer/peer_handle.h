#pragma once

#include <cstdint>

#include <common/error.h>
#include <common/collections/slot_pool.h>

#include <flux/peer/peer.h>

namespace bcp::flux
{
    /** RAII view of a peer living in PeerTable's SlotPool. Holds the slot's RW
        lock and drops it on destruction. Same shape as PacketSlotHandle with
        one difference: a PacketSlotHandle owns its slot and returns it to the
        pool when it dies, while a PeerHandle owns only the lock. The peer
        outlives the handle, and only PeerTable::RemovePeer frees the slot.

        A successful handle arrives already read-locked, with the key verified
        under that lock, which keeps the returned pointer safe: RemovePeer frees
        a slot only after write-locking it, and the write lock cannot be taken
        while any handle holds the read lock, so a peer is never freed under a
        live handle.

        @warning Drop the handle before removing the same peer from the same
                 thread, or RemovePeer waits on a lock the caller itself holds. */
    class PeerHandle
    {
    private:
        const Peer* peerR_ = nullptr;
              Peer* peerW_ = nullptr;

        uint32_t idx_{common::collections::SlotPool::INVALID};
        common::collections::SlotPool* pool_ = nullptr;

        enum class LockMode : uint8_t { NONE, READ, WRITE };
        LockMode lm_{LockMode::NONE};

        common::Error failReason_{common::Error::InvalidState};
        bool valid_{false};

    public:
        PeerHandle() = default;

        /** Built by PeerTable::GetPeer with the read lock already held. */
        PeerHandle(uint32_t index, common::collections::SlotPool* pool,
                   const Peer* lockedPeer)
            : peerR_(lockedPeer), idx_(index), pool_(pool),
              lm_(LockMode::READ), failReason_(common::Error::Ok), valid_(true) {}

        explicit PeerHandle(common::Error failReason)
            : failReason_(failReason) {}

        ~PeerHandle();

        PeerHandle(const PeerHandle&) = delete;
        PeerHandle& operator=(const PeerHandle&) = delete;

        PeerHandle(PeerHandle&& o) noexcept;
        PeerHandle& operator=(PeerHandle&& o) noexcept;

        /** Returns the peer while the handle is valid, nullptr after a move-out
            or on a failed handle. Never a pointer into a freed slot. */
        [[nodiscard]] const Peer* Read() noexcept;

        /** Upgrades to the write lock. Same caveat as PacketSlotHandle: the
            read lock is dropped before the write lock is taken, so another
            writer can slip between the two. Use with care. */
        [[nodiscard]] Peer* Write() noexcept;

        bool Failed() const;
        common::Error FailReason() const;

        uint32_t GetSlotIndex() const;

        static PeerHandle Invalid() noexcept { return PeerHandle{}; }

    private:
        void Steal(PeerHandle&& o) noexcept;
        void Invalidate() noexcept;

        /** Drops whatever lock is held. Never releases the slot; that is
            PeerTable's job, and doing it here would free a live peer. */
        void Unlock() noexcept;
    };
}
