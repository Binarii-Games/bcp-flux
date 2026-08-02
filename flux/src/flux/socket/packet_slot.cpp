#include <flux/socket/packet_slot.h>

#include <cstring>

#include <flux/socket/socket.h>          // Controls / ToByte
#include <flux/internal/constants.h>
#include <flux/socket/ready_lanes.h>
#include <flux/wire/batch.h>
#include <flux/wire/packet_builder.h>
#include <common/wire/bytes_reader.h>

namespace bcp::flux
{
    // --- PacketSlot ---
    bool PacketSlot::IsValid() const
    {
        if (dataSize < internal::MIN_WIRE_SIZE)
            return false;
        return true;
    }

    const uint8_t* PacketSlot::Controller() const
    {
        return &data[0];
    }

    bool PacketSlot::IsInternal() const
    {
        if (!IsValid())
            return false;
        return (Controller()[0] & ToByte(Controls::CTRL_INTERNAL)) != 0;
    }

    bool PacketSlot::IsSecure() const
    {
        if (!IsValid())
            return false;
        return (Controller()[0] & ToByte(Controls::CTRL_UNSECURE)) == 0;
    }

    bool PacketSlot::IsMacOnly() const
    {
        if (!IsValid())
            return false;
        return IsSecure() && (Controller()[0] & ToByte(Controls::CTRL_MACONLY)) != 0;
    }

    bool PacketSlot::IsBatch() const
    {
        if (!IsValid())
            return false;
        return (Controller()[0] & ToByte(Controls::CTRL_BATCH)) != 0;
    }

    bool PacketSlot::HasFlow() const
    {
        if (!IsValid())
            return false;
        return (Controller()[0] & ToByte(Controls::CTRL_HAS_FLOW)) != 0;
    }

    bool PacketSlot::IsTagged() const
    {
        if (!IsSecure())
            return false;
        return (Controller()[0] & ToByte(Controls::CTRL_TAGGED)) != 0;
    }

    size_t PacketSlot::FlowHeaderOffset() const
    {
        if (!HasFlow())
            return dataSize;

        size_t offset = internal::WIRE_CONTROLLER_SIZE;
        if (IsSecure())
            offset += internal::WIRE_NONCE_SIZE;
        if (IsTagged())
            offset += internal::WIRE_PEER_TAG_SIZE;
        if (IsSecure())
            offset += internal::WIRE_SECURE_CHANNEL_SIZE;   // flow fields follow the channel byte

        return offset + internal::WIRE_FLOW_HEADER_SIZE <= dataSize ? offset : dataSize;
    }

    uint16_t PacketSlot::FlowId() const
    {
        const size_t offset = FlowHeaderOffset();
        if (offset == dataSize)
            return internal::INVALID_FLOW_ID;

        common::BytesReader reader{ .p = data + offset, .r = internal::WIRE_FLOW_ID_SIZE };
        uint16_t flowId{};
        return reader.TakeU16(flowId) ? flowId : internal::INVALID_FLOW_ID;
    }

    uint32_t PacketSlot::FlowSeq() const
    {
        const size_t offset = FlowHeaderOffset();
        if (offset == dataSize)
            return 0;

        common::BytesReader reader{ .p = data + offset + internal::WIRE_FLOW_ID_SIZE,
                                    .r = internal::WIRE_FLOW_SEQ_SIZE };
        uint32_t seq{};
        return reader.TakeU32(seq) ? seq : 0;
    }

    uint8_t PacketSlot::FlowData() const
    {
        const size_t offset = FlowHeaderOffset();
        if (offset == dataSize)
            return 0;

        return data[offset + internal::WIRE_FLOW_ID_SIZE + internal::WIRE_FLOW_SEQ_SIZE];
    }

    FlowPart PacketSlot::Part() const
    {
        return FlowDataPart(FlowData());
    }

    const uint8_t* PacketSlot::PeerTagField() const
    {
        if (!IsTagged())
            return nullptr;
        constexpr size_t offset = internal::WIRE_CONTROLLER_SIZE
                                + internal::WIRE_NONCE_SIZE;
        if (offset + internal::WIRE_PEER_TAG_SIZE > dataSize)
            return nullptr;
        return data + offset;
    }

    uint8_t PacketSlot::SecureChannel() const
    {
        if (!IsSecure())
            return internal::SECURE_CHANNEL_APP;
        size_t offset = internal::WIRE_CONTROLLER_SIZE
                      + internal::WIRE_NONCE_SIZE;
        if (IsTagged())
            offset += internal::WIRE_PEER_TAG_SIZE;
        if (offset + internal::WIRE_SECURE_CHANNEL_SIZE > dataSize)
            return internal::SECURE_CHANNEL_APP;
        return data[offset];
    }

    size_t PacketSlot::ContentOffset() const
    {
        size_t contentOffset = internal::WIRE_CONTROLLER_SIZE;
        if (IsSecure())
            contentOffset += internal::WIRE_NONCE_SIZE;
        if (IsTagged())
            contentOffset += internal::WIRE_PEER_TAG_SIZE;
        if (IsSecure())
            contentOffset += internal::WIRE_SECURE_CHANNEL_SIZE;   // in-band channel byte
        if (HasFlow())
            contentOffset += internal::WIRE_FLOW_HEADER_SIZE;
        return contentOffset;
    }

    size_t PacketSlot::ContentLength() const
    {
        // The authentication tag sits after the payload on a secure packet, so
        // the content stops short of the end.
        const size_t trailer = IsSecure() ? internal::WIRE_TAG_SIZE : 0;
        const size_t used    = ContentOffset() + trailer;
        return used <= dataSize ? dataSize - used : 0;
    }

    const uint8_t* PacketSlot::Content(size_t offset) const
    {
        if (offset > dataSize) return nullptr;
        return data + offset;
    }

    // --- Handle ---
    PacketSlotHandle::~PacketSlotHandle()
    {
        Release();
    }

    PacketSlotHandle::PacketSlotHandle(PacketSlotHandle&& o)  noexcept
    {
        Steal(std::move(o));
    }

    PacketSlotHandle& PacketSlotHandle::operator=(PacketSlotHandle&& o) noexcept
    {
        Steal(std::move(o));
        return *this;
    }

    /** Caller must check the return for nullptr. */
    const PacketSlot* PacketSlotHandle::Read() noexcept
    {
        if (!valid_)
            return nullptr;
        
        if(lm_ == LockMode::READ)
        {
            return pktR_;
        }
        else if(lm_ == LockMode::WRITE)
        {
            lm_ = LockMode::READ;
            pktR_ = pktW_; 
            pool_->DowngradeLock(idx_);
            return pktR_;
        }

        pktR_ = reinterpret_cast<const PacketSlot*>(pool_->ReadLock(idx_));
        lm_ = LockMode::READ;
        return pktR_;
    }

    /** Caller must check the return for nullptr. */
    PacketSlot* PacketSlotHandle::Write() noexcept
    {
        if (!valid_)
            return nullptr;

        if(lm_ == LockMode::WRITE)
        {
            return pktW_;
        }
        else if(lm_ == LockMode::READ)
        {
            // Race if another write is claimed between the read unlock
            // and the write lock. Use with care.
            pktR_ = nullptr;
            pool_->UnlockRead(idx_);
        }

        pktW_ = reinterpret_cast<PacketSlot*>(pool_->WriteLock(idx_));
        lm_ = LockMode::WRITE;
        return pktW_;
    }

    wire::PacketBuilder PacketSlotHandle::PrepareResponse() noexcept
    {
        // Only Poll stamps a socket, so anything else (moved-from, detached,
        // internal) refuses here rather than sending through a socket it was
        // never given.
        if (!valid_ || !socket_)
            return wire::PacketBuilder{common::Error::InvalidState};

        const PacketSlot* packet = Read();
        if (!packet || !packet->address.IsSet())
            return wire::PacketBuilder{common::Error::InvalidParam};

        wire::PacketBuilder builder = socket_->BuildPacket();
        builder.Aim(packet->address);
        return builder;
    }

    bool PacketSlotHandle::Failed()
    {
        return failReason_ != common::Error::Ok;
    }

    common::Error PacketSlotHandle::FailReason()
    {
        return failReason_;
    }

    uint32_t PacketSlotHandle::GetStride()
    {
        return pool_->GetStride();
    }

    uint32_t PacketSlotHandle::GetSlotIndex() const
    {
        return idx_;
    }

    common::collections::SlotPool* PacketSlotHandle::GetPool() const
    {
        return pool_;
    }

    uint32_t PacketSlotHandle::Detach() noexcept
    {
        if (!valid_ || idx_ == common::collections::SlotPool::INVALID)
            return common::collections::SlotPool::INVALID;

        // The lock goes; the lease stays. Nothing else can reach this slot
        // (its only reference is the index we hand back), so holding the
        // lock across the wait would block the pool for no reader.
        switch (lm_)
        {
        case LockMode::READ:  pool_->UnlockRead(idx_);  break;
        case LockMode::WRITE: pool_->UnlockWrite(idx_); break;
        case LockMode::NONE:  break;
        }
        lm_ = LockMode::NONE;

        const uint32_t detached = idx_;
        pktR_ = nullptr;
        pktW_ = nullptr;
        idx_  = common::collections::SlotPool::INVALID;
        Invalidate();
        return detached;
    }

    void PacketSlotHandle::Steal(PacketSlotHandle&& o) noexcept
    {
        if (this == &o)
            return;

        Release();
        valid_ = o.valid_;
        failReason_ = o.failReason_;
        pktW_ = o.pktW_;
        pktR_ = o.pktR_;
        idx_ = o.idx_;
        pool_ = o.pool_;
        socket_ = o.socket_;
        lm_ = o.lm_;

        o.Invalidate();
    }

    void PacketSlotHandle::Invalidate() noexcept
    {
        valid_ = false;
        socket_ = nullptr;
    }

    void PacketSlotHandle::Release() noexcept
    {
        if(valid_ && (idx_ != common::collections::SlotPool::INVALID))
        {
            switch (lm_)
            {
            case LockMode::READ:
                pool_->UnlockRead(idx_);
                // common::LogF(common::LogLevel::Info, "Unlock Read: %u", idx_);
                break;
            case LockMode::WRITE:
                pool_->UnlockWrite(idx_);
                // common::LogF(common::LogLevel::Info, "Unlock Write: %u", idx_);
                break;
            case LockMode::NONE:
                break;
            }

            // common::LogF(common::LogLevel::Info, "Release: %u", idx_);

            pool_->Release(idx_);
            Invalidate();
        }
    }

    // --- Writer ---
    PacketSlotWriter::PacketSlotWriter(PacketSlotHandle handle) noexcept
        : handle_(std::move(handle))
    {
        if  (handle_.Failed())
        {
            pkt_ = nullptr;
            cursor_ = common::BytesWriter  
            {
                .p = nullptr,
                .l = nullptr,
                .r = 0
            };
            return;
        }

        pkt_ = handle_.Write();

        // The pool recycles slots without clearing them, and the cursor
        // accumulates into dataSize, so a stale length from the previous
        // tenant would inflate every packet built over a reused slot. The
        // writer owns the slot's initialization: length starts at zero.
        pkt_->dataSize = 0;
        cursor_ = common::BytesWriter
        {
            .p = pkt_->data,
            .l = &pkt_->dataSize,
            .r = handle_.GetStride() - sizeof(PacketSlot)
        };
    }

    bool PacketSlotWriter::WriteAddress(Address address)
    {
        pkt_->address = address;
        return true;
    }

    bool PacketSlotWriter::ReserveSecureHeader(bool tagged)
    {
        size_t reserved = internal::WIRE_NONCE_SIZE;
        if (tagged)
            reserved += internal::WIRE_PEER_TAG_SIZE;
        // The tag is appended by the seal, past whatever the caller writes, so
        // its room is taken out of the budget here without moving the cursor.
        if (cursor_.r < reserved + internal::WIRE_TAG_SIZE) return false;
        cursor_.r -= internal::WIRE_TAG_SIZE;
        std::memset(cursor_.p, 0, reserved);
        cursor_.p += reserved;
        cursor_.r -= reserved;
        cursor_.IncrLenght(reserved);
        return true;
    }

    bool PacketSlotWriter::PutU8(uint8_t in)
    {
        return cursor_.PutU8(in);
    }

    bool PacketSlotWriter::PutU16(uint16_t in)
    {
        return cursor_.PutU16(in);
    }

    bool PacketSlotWriter::PutU32(uint32_t in)
    {
        return cursor_.PutU32(in);
    }

    bool PacketSlotWriter::PutU64(uint64_t in)
    {
        return cursor_.PutU64(in);
    }

    bool PacketSlotWriter::PutBytes(const uint8_t* data, size_t len)
    {
        return cursor_.PutBytes(data, len);
    }

    uint32_t PacketSlotWriter::GetSlotIndex() const
    {
        return handle_.GetSlotIndex();
    }

    PacketSlotHandle PacketSlotWriter::ExtractHandle() && noexcept
    {
        // Lost handle ownership, make the writer clearly unusable
        pkt_ = nullptr;
        cursor_ = common::BytesWriter
        {
            .p = nullptr,
            .l = nullptr,
            .r = 0
        };
        return std::move(handle_);
    }

    bool PacketSlotWriter::Failed()
    {
        return handle_.Failed();
    }

    common::Error PacketSlotWriter::FailReason()
    {
        return handle_.FailReason();
    }

    // --- Reader ---
    PacketSlotReader::PacketSlotReader(PacketSlotHandle& handle) noexcept
        : pkt_(nullptr)
        , cursor_{.p = nullptr, .r = 0}
        , failReason_(handle.FailReason())
        , content_(nullptr)
        , contentLen_(0)
        , walkOffset_(0)
        , message_(nullptr)
        , messageLen_(0)
    {
        if (handle.Failed())
            return;

        pkt_ = handle.Read();
        if (!pkt_)
            return;

        const size_t offset = pkt_->ContentOffset();
        if (offset > pkt_->dataSize)
            return;

        content_ = pkt_->Content(offset);
        // ContentLength, not dataSize - offset: a secure packet ends in the
        // AEAD tag, which is framing and not payload, so a length-driven or
        // read-to-exhaustion caller must not see it.
        contentLen_ = static_cast<uint16_t>(pkt_->ContentLength());

        if (pkt_->IsBatch())
        {
            // Reading an entry the chain does not account for means trusting
            // bytes chosen by whatever damaged it, so a batch that does not
            // walk cleanly yields nothing at all.
            if (!wire::BatchValidate(content_, contentLen_)
                || !wire::BatchNext(content_, contentLen_, walkOffset_, message_, messageLen_))
            {
                content_ = nullptr;
                message_ = nullptr;
                messageLen_ = 0;
                failReason_ = common::Error::InvalidHeader;
                return;
            }
        }
        else
        {
            message_    = content_;
            messageLen_ = contentLen_;
            walkOffset_ = contentLen_;
        }

        cursor_ = common::BytesReader
        {
            .p = message_,
            .r = messageLen_
        };
    }

    bool PacketSlotReader::NextMessage() noexcept
    {
        if (!content_ || walkOffset_ >= contentLen_)
            return false;

        if (!wire::BatchNext(content_, contentLen_, walkOffset_, message_, messageLen_))
            return false;

        cursor_ = common::BytesReader
        {
            .p = message_,
            .r = messageLen_
        };
        return true;
    }

    bool PacketSlotReader::TakeU8(uint8_t& out)
    {
        return cursor_.TakeU8(out);
    }

    bool PacketSlotReader::TakeU16(uint16_t& out)
    {
        return cursor_.TakeU16(out);
    }

    bool PacketSlotReader::TakeU32(uint32_t& out)
    {
        return cursor_.TakeU32(out);
    }

    bool PacketSlotReader::TakeU64(uint64_t& out)
    {
        return cursor_.TakeU64(out);
    }

    bool PacketSlotReader::TakeBytes(uint8_t* dst, size_t len)
    {
        return cursor_.TakeBytes(dst, len);
    }

    // --- PollCursor ---
    PollCursor::PollCursor(ReadyLanes* lanes, uint32_t lane,
                           PacketSlotHandle* slots, uint32_t count) noexcept
        : lanes_(lanes)
        , lane_(lane)
        , slots_(slots)
        , count_(slots ? count : 0)
        , index_(0)
        , opened_(false)
        , none_(PacketSlotHandle::Invalid())
        , reader_(none_)
    {
    }

    PollCursor::~PollCursor()
    {
        if (lanes_) lanes_->Release(lane_);
    }

    PollCursor::PollCursor(PollCursor&& o) noexcept
        : lanes_(o.lanes_)
        , lane_(o.lane_)
        , slots_(o.slots_)
        , count_(o.count_)
        , index_(o.index_)
        , opened_(o.opened_)
        , none_(PacketSlotHandle::Invalid())
        , reader_(none_)
    {
        reader_ = o.reader_;
        o.lanes_ = nullptr;   // the claim moves with the cursor
    }

    PollCursor& PollCursor::operator=(PollCursor&& o) noexcept
    {
        if (this == &o) return *this;
        if (lanes_) lanes_->Release(lane_);
        lanes_  = o.lanes_;
        lane_   = o.lane_;
        slots_  = o.slots_;
        count_  = o.count_;
        index_  = o.index_;
        opened_ = o.opened_;
        reader_ = o.reader_;
        o.lanes_ = nullptr;
        return *this;
    }

    bool PollCursor::Next() noexcept
    {
        while (index_ < count_)
        {
            if (!opened_)
            {
                opened_ = true;
                reader_ = PacketSlotReader{slots_[index_]};
                if (!reader_.Failed())
                    return true;
            }
            else if (reader_.NextMessage())
            {
                return true;
            }

            // A packet that would not open is skipped whole: its framing is
            // damaged, so there is no next message to move to.
            ++index_;
            opened_ = false;
        }

        reader_ = PacketSlotReader{none_};
        return false;
    }

    bool PacketSlotReader::Failed()
    {
        return failReason_ != common::Error::Ok;
    }

    common::Error PacketSlotReader::FailReason()
    {
        return failReason_;
    }
}