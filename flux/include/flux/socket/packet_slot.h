#pragma once

#include <cstdint>
#include <utility>

#include <common/log.h>
#include <common/result.h>
#include <common/error.h>
#include <common/collections/slot_pool.h>
#include <common/wire/bytes_reader.h>
#include <common/wire/bytes_writer.h>

#include <flux/address.h>

namespace bcp::flux
{
    /** The packet as it sits in a pool slot: a small header followed by the raw
        wire bytes as a flexible array. PacketSlotHandle/Writer/Reader below are
        the RAII accessors that lock, read, and write one of these.

        Wire layout, driven by independent controller bits:
          secure    (CTRL_UNSECURE clear): [Controller(1)][Tag(16)][NonceCounter(8)][PeerTag(4)?] || [Channel(1)][...]
          unsecured (CTRL_UNSECURE set):   [Controller(1)][...]
        [PeerTag(4)?] is present when CTRL_TAGGED is set (the migration handle).
        On a secure packet everything after the header (the ||) is ciphertext:
        a one-byte in-band Channel (0 for application data, else an internal
        control op), then [FlowId(2)][FlowSeq(4)] when CTRL_HAS_FLOW is set,
        then the payload. The controller byte and peer tag are authenticated
        associated data, readable on the wire but not alterable; the channel
        byte is encrypted, so an observer cannot tell control from data.
        SecureChannel() is meaningful only after a successful decrypt.
        NonceCounter is masked under a per-packet value, so it reads as noise
        rather than as a sequence an observer could follow across an address
        change.
     */
    struct PacketSlot
    {
        Address address;
        uint16_t dataSize;
        uint8_t data[];

        bool IsValid() const;
        const uint8_t* Controller() const;
        bool IsInternal() const;
        bool IsSecure() const;
        bool HasFlow() const;
        /** Secure packet carrying the 4-byte migration tag (CTRL_TAGGED). */
        bool IsTagged() const;
        uint16_t FlowId() const;
        /** The flow sequence number of a flow packet; 0 (the never-sent
            sentinel) when the packet carries no flow or is too short. */
        uint32_t FlowSeq() const;
        /** The 8-byte counter field exactly as transmitted; 0 on an unsecured
            packet.

            @warning On a secure packet this is the MASKED value, not the send
                     counter — the field is encrypted so that an observer
                     cannot follow a peer by its counter sequence. Only
                     Socket::OpenSecurePacket recovers the real counter. */
        uint64_t NonceCounter() const;
        /** The peer-tag field of a tagged packet; nullptr when not tagged or
            the packet is too short to hold one. */
        const uint8_t* PeerTagField() const;
        /** The in-band channel byte of a secure packet, read post-decrypt; 0
            (SECURE_CHANNEL_APP) when not secure or too short to carry one. */
        uint8_t SecureChannel() const;
        size_t ContentOffset() const;
        const uint8_t* Content(size_t offset) const; ///< For read only.
    };

    class PacketSlotHandle
    {
    // Automatically manages socket slot lifetime and locks.
    private:
        const PacketSlot* pktR_ = nullptr;
              PacketSlot* pktW_ = nullptr;

        uint32_t idx_{common::collections::SlotPool::INVALID};
        common::collections::SlotPool* pool_ = nullptr;
     
        enum class LockMode : uint8_t {NONE, READ, WRITE};
        LockMode lm_{LockMode::NONE};
     
        common::Error failReason_{common::Error::InvalidState};
        bool valid_{false};

    public:
        PacketSlotHandle() = default;

        /** An INVALID index (or null pool) yields a failed handle whose Read/
            Write return nullptr; a wild index can never become a wild pointer.
            Slots travel between components only as handles or bare indices
            rebuilt through this constructor, so this is the one gate. */
        PacketSlotHandle(uint32_t index, common::collections::SlotPool* pool)
            : idx_(index), pool_(pool),
              failReason_{(index != common::collections::SlotPool::INVALID && pool != nullptr)
                              ? common::Error::Ok : common::Error::InvalidParam},
              valid_(index != common::collections::SlotPool::INVALID && pool != nullptr) {}
        PacketSlotHandle(common::Error failReason, common::collections::SlotPool* pool)
            : idx_(common::collections::SlotPool::INVALID), pool_(pool), failReason_(failReason), valid_(false) {}

        ~PacketSlotHandle();

        PacketSlotHandle(const PacketSlotHandle& o) = delete;
        PacketSlotHandle& operator=(const PacketSlotHandle&) = delete;

        PacketSlotHandle(PacketSlotHandle&& o) noexcept;
        PacketSlotHandle& operator=(PacketSlotHandle&& o) noexcept;

        [[nodiscard]]const PacketSlot* Read() noexcept;
        [[nodiscard]]      PacketSlot* Write() noexcept;

        bool Failed();
        common::Error FailReason();

        uint32_t GetStride();
        uint32_t GetSlotIndex() const;

        /** Which pool the slot came from. The send path compares it to tell a
            retained body (staging) from an ordinary one; the receive path uses
            it to rebuild handles for packets it parked by index (ordered
            hold-back), so it is not const. */
        common::collections::SlotPool* GetPool() const;

        /** Gives up ownership: drops any lock, returns the slot index, and
            leaves the handle invalid so its destructor releases nothing. The
            detached slot belongs to the caller alone until it is Released back
            to the pool, the same contract as pending::PopFront reached from a
            handle instead of a peer's list. This is how a packet body outlives
            the send that wrote it (a reliable flow keeps its plaintext as the
            retransmit source; copying it would put an allocation-free path's
            payload through a memcpy).

            @return SlotPool::INVALID on an already-invalid handle, which owns
                    nothing to hand over. */
        [[nodiscard]] uint32_t Detach() noexcept;

        static PacketSlotHandle Invalid() noexcept
        {
            return PacketSlotHandle{};
        }

    private:
        void Steal(PacketSlotHandle&& o) noexcept;
        void Invalidate() noexcept;
        void Release() noexcept;
    };

    
    class PacketSlotWriter
    {
    private:
        PacketSlot* pkt_;
        PacketSlotHandle handle_;
        common::BytesWriter cursor_;

    public:
        /** A failed handle yields a writer that holds no slot and fails every
            Put, the state to hand back when no slot could be acquired. */
        PacketSlotWriter(PacketSlotHandle handle) noexcept;

        bool WriteAddress(Address address);
        /** Reserves the tag and nonce fields (plus the peer-tag field when
            tagged), zero-filled; they are stamped at send time once the peer's
            counter, key, and current tag are known.

            @pre Called right after the controller byte on a secure packet. */
        bool ReserveSecureHeader(bool tagged);

        bool PutU8(uint8_t in);
        bool PutU16(uint16_t in);
        bool PutU32(uint32_t in);
        bool PutU64(uint64_t in);
        bool PutBytes(const uint8_t* data, size_t len);

        uint32_t GetSlotIndex() const;
        PacketSlotHandle ExtractHandle() && noexcept;

        bool Failed();
        common::Error FailReason();
    };

    
    class PacketSlotReader 
    {
    private:
        const PacketSlot* pkt_;
        PacketSlotHandle handle_;
        common::BytesReader cursor_;

    public:
        PacketSlotReader(PacketSlotHandle handle) noexcept;

        bool TakeU8(uint8_t& out);
        bool TakeU16(uint16_t& out);
        bool TakeU32(uint32_t& out);
        bool TakeU64(uint64_t& out);
        bool TakeBytes(uint8_t* dst, size_t len);

        PacketSlotHandle ExtractHandle() && noexcept;

        bool Failed();
        common::Error FailReason();
    };
}