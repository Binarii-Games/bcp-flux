#include <flux/socket/platform/faulty_socket.h>

#include <mutex>

#include <cstring>

#include <common/platform.h>

#include <flux/internal/constants.h>
#include <flux/socket/socket.h>   // Controls, for the cleartext handshake bit

namespace bcp::flux::platform
{
    namespace
    {
        /** xorshift64star. Small, fast, and the same everywhere, which is what
            makes a seeded run replay on another machine. */
        constexpr uint64_t DEFAULT_SEED = 0x9E3779B97F4A7C15ull;

        bool IsInternalByte(uint8_t controller) noexcept
        {
            return (controller & static_cast<uint8_t>(Controls::CTRL_INTERNAL)) != 0;
        }

        /** Bound sockets, so a test can find the one it just handed to a
            Socket. Fixed and small: a test drives a handful at once. */
        constexpr uint32_t MAX_BOUND = 16;
        FaultySocket* g_bound[MAX_BOUND] = {};
        uint16_t      g_boundPort[MAX_BOUND] = {};
    }

    FaultySocket* FaultySocket::ForPort(uint16_t port) noexcept
    {
        for (uint32_t i = 0; i < MAX_BOUND; ++i)
            if (g_bound[i] != nullptr && g_boundPort[i] == port) return g_bound[i];
        return nullptr;
    }

    common::Error FaultySocket::Init(int port, uint32_t recvSlotCount, uint32_t sendSlotCount)
    {
        std::lock_guard<std::recursive_mutex> guard(mutex_);
        rng_ = profile_.seed != 0 ? profile_.seed : DEFAULT_SEED;
        const common::Error opened = FaultyBase::Init(port, recvSlotCount, sendSlotCount);
        if (opened != common::Error::Ok) return opened;

        boundPort_ = static_cast<uint16_t>(port);
        for (uint32_t i = 0; i < MAX_BOUND; ++i)
        {
            if (g_bound[i] != nullptr) continue;
            g_bound[i] = this;
            g_boundPort[i] = boundPort_;
            break;
        }
        return common::Error::Ok;
    }

    void FaultySocket::Close()
    {
        std::lock_guard<std::recursive_mutex> guard(mutex_);
        for (uint32_t i = 0; i < MAX_HELD; ++i)
            held_[i].occupied = false;
        for (uint32_t i = 0; i < MAX_BOUND; ++i)
            if (g_bound[i] == this) { g_bound[i] = nullptr; g_boundPort[i] = 0; }
        FaultyBase::Close();
    }

    void FaultySocket::SetProfile(const Profile& profile) noexcept
    {
        std::lock_guard<std::recursive_mutex> guard(mutex_);
        profile_ = profile;
        rng_ = profile.seed != 0 ? profile.seed : DEFAULT_SEED;
    }

    void FaultySocket::DropNext(uint32_t count) noexcept    { std::lock_guard<std::recursive_mutex> guard(mutex_); dropNext_    += count; }
    void FaultySocket::CorruptNext(uint32_t count) noexcept { std::lock_guard<std::recursive_mutex> guard(mutex_); corruptNext_ += count; }
    void FaultySocket::DropAt(uint64_t ordinal) noexcept    { std::lock_guard<std::recursive_mutex> guard(mutex_); dropAt_       = ordinal; }
    void FaultySocket::BlockHandshakes(bool blocked) noexcept { std::lock_guard<std::recursive_mutex> guard(mutex_); blockHandshakes_ = blocked; }

    void FaultySocket::DelayNext(uint32_t count, uint32_t micros) noexcept
    {
        std::lock_guard<std::recursive_mutex> guard(mutex_);
        delayNext_   += count;
        delayMicros_  = micros;
    }

    uint32_t FaultySocket::NextRandom() noexcept
    {
        rng_ ^= rng_ >> 12;
        rng_ ^= rng_ << 25;
        rng_ ^= rng_ >> 27;
        return static_cast<uint32_t>((rng_ * 0x2545F4914F6CDD1Dull) >> 32);
    }

    bool FaultySocket::RollPercent(uint8_t percent) noexcept
    {
        if (percent == 0)   return false;
        if (percent >= 100) return true;
        return (NextRandom() % 100u) < percent;
    }

    bool FaultySocket::IsHandshake(const uint8_t* data, uint16_t size) noexcept
    {
        // The controller byte is cleartext, so this is the same classification
        // any observer on the path could make.
        return size >= internal::WIRE_CONTROLLER_SIZE && IsInternalByte(data[0]);
    }

    bool FaultySocket::ShouldDrop(const uint8_t* data, uint16_t size) noexcept
    {
        const bool handshake = IsHandshake(data, size);

        if (blockHandshakes_ && handshake)
        {
            ++stats_.handshakesDropped;
            return true;
        }
        if (dropAt_ == ordinal_)
        {
            dropAt_ = UINT64_MAX;
            if (handshake) ++stats_.handshakesDropped;
            return true;
        }
        if (dropNext_ > 0)
        {
            --dropNext_;
            if (handshake) ++stats_.handshakesDropped;
            return true;
        }

        // A burst under way keeps discarding without consulting the dice, which
        // is what makes it a burst rather than a run of independent losses.
        if (burstRemaining_ > 0)
        {
            --burstRemaining_;
            if (handshake) ++stats_.handshakesDropped;
            return true;
        }

        if (handshake && RollPercent(profile_.handshakeLossPercent))
        {
            ++stats_.handshakesDropped;
            return true;
        }
        if (RollPercent(profile_.lossPercent))
        {
            burstRemaining_ = profile_.burstLoss > 1
                ? static_cast<uint16_t>(profile_.burstLoss - 1) : 0;
            if (handshake) ++stats_.handshakesDropped;
            return true;
        }
        return false;
    }

    bool FaultySocket::Hold(const sockaddr_storage& target, const uint8_t* data,
                            uint16_t size, uint64_t dueMicros, uint32_t releaseAfter) noexcept
    {
        for (uint32_t i = 0; i < MAX_HELD; ++i)
        {
            if (held_[i].occupied) continue;
            held_[i].target       = target;
            held_[i].size         = size;
            held_[i].dueMicros    = dueMicros;
            held_[i].releaseAfter = releaseAfter;
            held_[i].occupied     = true;
            std::memcpy(held_[i].data, data, size);
            return true;
        }
        return false;   // no room to hold it: the caller sends it straight out
    }

    void FaultySocket::ReleaseDue() noexcept
    {
        const uint64_t now = common::MonotonicMicros();
        for (uint32_t i = 0; i < MAX_HELD; ++i)
        {
            Held& slot = held_[i];
            if (!slot.occupied) continue;
            if (slot.releaseAfter > 0)
            {
                --slot.releaseAfter;
                continue;
            }
            if (slot.dueMicros > now) continue;

            slot.occupied = false;
            (void)Emit(slot.target, slot.data, slot.size);
        }
    }

    common::Error FaultySocket::Emit(const sockaddr_storage& target,
                                     const uint8_t* data, uint16_t size) noexcept
    {
        ++stats_.sent;
        return FaultyBase::SendTo(target, data, size);
    }

    common::Error FaultySocket::SendTo(const sockaddr_storage& target,
                                       const uint8_t* data, uint16_t size)
    {
        std::lock_guard<std::recursive_mutex> guard(mutex_);
        // Anything owed from an earlier call goes first, so a held packet is
        // never overtaken by one held after it.
        ReleaseDue();

        const bool applies = profile_.applyTo == Direction::Send
                          || profile_.applyTo == Direction::Both;
        if (!applies)
            return Emit(target, data, size);

        const uint64_t ordinal = ordinal_++;
        (void)ordinal;

        if (ShouldDrop(data, size))
        {
            ++stats_.dropped;
            return common::Error::Ok;   // a dropped packet is not a send failure
        }

        // Corruption flips one bit in the body rather than the header, so the
        // packet still routes and still parses far enough to reach the seal,
        // which is the check that has to catch it.
        uint8_t  scratch[internal::MAX_WIRE_PACKET_SIZE];
        const uint8_t* payload = data;
        if (corruptNext_ > 0 || RollPercent(profile_.corruptPercent))
        {
            if (corruptNext_ > 0) --corruptNext_;
            std::memcpy(scratch, data, size);
            const uint16_t at = size > internal::WIRE_CONTROLLER_SIZE
                ? static_cast<uint16_t>(internal::WIRE_CONTROLLER_SIZE
                                        + (NextRandom() % (size - internal::WIRE_CONTROLLER_SIZE)))
                : 0;
            scratch[at] ^= static_cast<uint8_t>(1u << (NextRandom() % 8u));
            payload = scratch;
            ++stats_.corrupted;
        }

        uint64_t due = 0;
        uint32_t after = 0;
        if (delayNext_ > 0)
        {
            --delayNext_;
            due = common::MonotonicMicros() + delayMicros_;
            ++stats_.delayed;
        }
        else if (profile_.latencyMicros != 0 || profile_.jitterMicros != 0)
        {
            const uint32_t jitter = profile_.jitterMicros != 0
                ? NextRandom() % profile_.jitterMicros : 0;
            due = common::MonotonicMicros() + profile_.latencyMicros + jitter;
            ++stats_.delayed;
        }
        if (RollPercent(profile_.reorderPercent))
        {
            after = profile_.reorderDepth;
            ++stats_.reordered;
        }

        if ((due != 0 || after != 0) && Hold(target, payload, size, due, after))
            return common::Error::Ok;

        const common::Error result = Emit(target, payload, size);

        // A duplicate is the same bytes a second time, which is what the seen
        // bitmap and the replay window exist to absorb.
        if (result == common::Error::Ok && RollPercent(profile_.duplicatePercent))
        {
            ++stats_.duplicated;
            (void)Emit(target, payload, size);
        }
        return result;
    }

    common::Result<uint32_t> FaultySocket::ReceiveFrom(PacketSlotHandle* outPackets,
                                                       uint32_t maxCount)
    {
        std::lock_guard<std::recursive_mutex> guard(mutex_);
        // The tick calls this often, which makes it the natural place to let
        // held packets out even when nothing is being sent.
        ReleaseDue();

        common::Result<uint32_t> result = FaultyBase::ReceiveFrom(outPackets, maxCount);
        if (result.isErr())
            return result;

        const uint32_t count = result.Take();
        const bool applies = profile_.applyTo == Direction::Receive
                          || profile_.applyTo == Direction::Both;
        if (!applies)
        {
            stats_.received += count;
            return common::Result<uint32_t>::Success(count);
        }

        // Discard in place and close the gap, so the caller sees a shorter
        // batch rather than holes it has to skip.
        uint32_t kept = 0;
        for (uint32_t i = 0; i < count; ++i)
        {
            const PacketSlot* packet = outPackets[i].Read();
            const uint8_t* data = packet ? packet->data : nullptr;
            const uint16_t size = packet ? packet->dataSize : 0;

            ++ordinal_;
            if (data && ShouldDrop(data, size))
            {
                ++stats_.dropped;
                outPackets[i] = PacketSlotHandle::Invalid();   // releases the slot
                continue;
            }
            if (kept != i)
                outPackets[kept] = std::move(outPackets[i]);
            ++kept;
        }
        stats_.received += kept;
        return common::Result<uint32_t>::Success(kept);
    }
}
