#include <flux/peer/peer_handle.h>

#include <utility>

namespace bcp::flux
{
    PeerHandle::~PeerHandle()
    {
        Unlock();
    }

    PeerHandle::PeerHandle(PeerHandle&& o) noexcept
    {
        Steal(std::move(o));
    }

    PeerHandle& PeerHandle::operator=(PeerHandle&& o) noexcept
    {
        Steal(std::move(o));
        return *this;
    }

    const Peer* PeerHandle::Read() noexcept
    {
        if (!valid_)
            return nullptr;

        if (lm_ == LockMode::READ)
            return peerR_;

        if (lm_ == LockMode::WRITE)
        {
            peerR_ = peerW_;
            peerW_ = nullptr;
            lm_ = LockMode::READ;
            pool_->DowngradeLock(idx_);
            return peerR_;
        }

        peerR_ = reinterpret_cast<const Peer*>(pool_->ReadLock(idx_));
        lm_ = LockMode::READ;
        return peerR_;
    }

    Peer* PeerHandle::Write() noexcept
    {
        if (!valid_)
            return nullptr;

        if (lm_ == LockMode::WRITE)
            return peerW_;

        if (lm_ == LockMode::READ)
        {
            peerR_ = nullptr;
            pool_->UnlockRead(idx_);
        }

        peerW_ = reinterpret_cast<Peer*>(pool_->WriteLock(idx_));
        lm_ = LockMode::WRITE;
        return peerW_;
    }

    bool PeerHandle::Failed() const
    {
        return failReason_ != common::Error::Ok;
    }

    common::Error PeerHandle::FailReason() const
    {
        return failReason_;
    }

    uint32_t PeerHandle::GetSlotIndex() const
    {
        return idx_;
    }

    void PeerHandle::Steal(PeerHandle&& o) noexcept
    {
        if (this == &o)
            return;

        Unlock();
        peerR_      = o.peerR_;
        peerW_      = o.peerW_;
        idx_        = o.idx_;
        pool_       = o.pool_;
        lm_         = o.lm_;
        failReason_ = o.failReason_;
        valid_      = o.valid_;

        o.Invalidate();
    }

    void PeerHandle::Invalidate() noexcept
    {
        valid_ = false;
        lm_    = LockMode::NONE;
        peerR_ = nullptr;
        peerW_ = nullptr;
    }

    void PeerHandle::Unlock() noexcept
    {
        if (valid_ && idx_ != common::collections::SlotPool::INVALID)
        {
            switch (lm_)
            {
                case LockMode::READ:
                    pool_->UnlockRead(idx_);
                    break;
                case LockMode::WRITE:
                    pool_->UnlockWrite(idx_);
                    break;
                case LockMode::NONE:
                    break;
            }
        }
        Invalidate();
    }
}
