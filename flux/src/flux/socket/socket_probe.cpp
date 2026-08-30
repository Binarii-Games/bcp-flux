// The probe: measuring how far away an address is without speaking to it.
//
// Everything else in this library that learns a round trip learns it as a side
// effect of a conversation. A flow numbers its packets, the far side
// acknowledges them, and the gap between the two is a sample. That is the right
// way to measure a peer you are already talking to, and it costs nothing extra,
// but it can only answer a question you have already committed to: it tells you
// what the path to somebody you chose is like, after choosing.
//
// A caller with several candidates and one choice to make needs the opposite.
// It wants to know what each of them costs BEFORE picking one, and it wants to
// ask without opening a session with every one of them, because a session is a
// relationship - a peer slot, a handshake, keys, an entry that has to be aged
// out - and paying that for candidates it is about to discard would be worse
// than not asking at all.
//
// So the exchange here deliberately leaves nothing behind on either side. Two
// unsecured packets carry a token out and back. The answering socket keeps
// nothing whatsoever: it copies the token into a reply and forgets, which is
// what makes a flood of probes cost it a bounded number of replies per tick and
// no memory. The asking socket keeps one slot until the answer arrives or the
// wait expires, and the token is that slot's own handle, so a reply for a slot
// that has since been reused fails its generation check rather than being
// credited to whoever holds it now.
//
// Two consequences follow from being unauthenticated, and both are settled
// here rather than left to the caller:
//
// A probe cannot be a lever. Anyone may write somebody else's address as the
// source and collect the answer on their behalf, so the answer must never
// outweigh the question - a probe pads itself up to the weight of the reply it
// asks for, and a probe that arrives underweight is dropped rather than
// answered. Shrinking traffic is no use to a reflector.
//
// A probe cannot move anything a session depends on. The measurement goes back
// to the caller, and it seeds the smoothed round trip of a peer at that address
// only where nothing has been measured yet - never the windowed minimum, which
// exists to describe the path as acknowledged data experiences it, and never
// the liveness stamp, because being asked a question is not evidence of being
// in a conversation. RttEstimate::SeedFromProbe carries the full reasoning.
#include <flux/socket/socket.h>

#include <common/platform.h>
#include <common/wire/bytes_reader.h>


namespace bcp::flux
{
    namespace
    {
        /** The token a slot answers to: its generation over its index, the same
            number scheme peers and packets use. Zero is never a live token,
            because a slot's first generation is one, so a reply carrying zero
            can be refused without a lookup. */
        constexpr uint64_t ProbeToken(uint32_t slot, uint32_t generation) noexcept
        {
            return (static_cast<uint64_t>(generation) << 32) | slot;
        }

        constexpr uint32_t ProbeSlotOf(uint64_t token) noexcept
        {
            return static_cast<uint32_t>(token & 0xFFFFFFFFull);
        }

        constexpr uint32_t ProbeGenerationOf(uint64_t token) noexcept
        {
            return static_cast<uint32_t>(token >> 32);
        }

        /** A reader over a probe's body, which starts after the controller and
            the opcode. Fixed offsets rather than a message cursor: the cursor
            honours the batch bit, and anything may set that on a cleartext
            packet, so reading through it would let a stranger decide whether a
            probe parses at all. */
        common::BytesReader ProbeBody(const PacketSlot& packet) noexcept
        {
            constexpr size_t head = internal::WIRE_CONTROLLER_SIZE + 1;
            return common::BytesReader{ packet.data + head,
                                        packet.dataSize > head ? packet.dataSize - head : 0 };
        }
    }

    common::Error Socket::ProbeAddress(const Address& addr)
    {
        if (!initialized_.load(std::memory_order_acquire)) return common::Error::NotInitialized;
        if (probes_ == nullptr || probeCount_ == 0) return common::Error::NotInitialized;

        // Claim a free slot. CLAIMING is the state that keeps a second claimer
        // out while the fields are filled: nothing reads a slot in it, and the
        // release store at the end is what publishes the fields with it.
        for (uint32_t i = 0; i < probeCount_; ++i)
        {
            ProbeSlot& slot = probes_[i];
            uint32_t expected = static_cast<uint32_t>(ProbeState::FREE);
            if (!slot.state.compare_exchange_strong(
                    expected, static_cast<uint32_t>(ProbeState::CLAIMING),
                    std::memory_order_acq_rel, std::memory_order_relaxed))
                continue;

            // The generation moves on every claim, so the token this probe
            // sends can never be answered into the slot's next occupant.
            const uint32_t generation =
                slot.generation.fetch_add(1, std::memory_order_relaxed) + 1;

            slot.addr         = addr;
            slot.sentAtMicros = common::MonotonicMicros();
            slot.rttMicros    = 0;

            slot.state.store(static_cast<uint32_t>(ProbeState::OUTSTANDING),
                             std::memory_order_release);

            SendProbe(addr, ProbeToken(i, generation));
            return common::Error::Ok;
        }

        // Every slot is waiting on an answer. Refusing is the honest reply: the
        // caller decides whether an older question matters less than this one,
        // and nothing here can know that.
        return common::Error::LimitReached;
    }

    void Socket::SendProbe(const Address& addr, uint64_t token)
    {
        common::Result<PacketSlotWriter> result = BuildInternal(SocketOpCode::PROBE);
        if (result.isErr()) return;
        PacketSlotWriter writer = result.Take();

        writer.WriteAddress(addr);
        writer.PutU64(token);

        // The padding that makes the question weigh at least what the answer
        // does. Its contents are never read; only its presence is.
        uint8_t pad[internal::PROBE_PAD_SIZE] = {};
        writer.PutBytes(pad, sizeof(pad));

        // Probe traffic bypasses the flow gate for the same reason handshake
        // traffic does, and a lost one is not retried: the wait expires and the
        // caller is told, which is the only failure a probe has.
        (void)sender_.Send(std::move(writer).ExtractHandle());
    }

    void Socket::Probe_Respond(const Address& from, const PacketSlot& packet)
    {
        // Underweight probes are dropped rather than answered. This is the
        // anti-reflection rule and it has to run before anything is sent, since
        // sending is the whole thing being denied.
        if (packet.dataSize < internal::PROBE_MIN_WIRE_SIZE) return;

        // Bounded per tick. An answer is cheap, but cheap for a flood too, so
        // the excess is dropped and the asker's own retry covers it.
        if (probeBudgetThisTick_ == 0) return;
        --probeBudgetThisTick_;

        common::BytesReader body = ProbeBody(packet);
        uint64_t token = 0;
        if (!body.TakeU64(token)) return;

        common::Result<PacketSlotWriter> result = BuildInternal(SocketOpCode::PROBE_ACK);
        if (result.isErr()) return;
        PacketSlotWriter writer = result.Take();

        writer.WriteAddress(from);
        writer.PutU64(token);

        // Nothing is held: the reply is built where the probe is read, so the
        // figure is zero and says so honestly. It travels anyway, because the
        // prober subtracts whatever is here, and a later version of this path
        // that defers a reply must be able to say so without a wire change.
        writer.PutU32(0);

        (void)sender_.Send(std::move(writer).ExtractHandle());
    }

    void Socket::Probe_Complete(const Address& from, const PacketSlot& packet)
    {
        if (packet.dataSize < internal::PROBE_ACK_WIRE_SIZE) return;

        common::BytesReader body = ProbeBody(packet);
        uint64_t token = 0;
        uint32_t held  = 0;
        if (!body.TakeU64(token)) return;
        if (!body.TakeU32(held))  return;

        const uint32_t index = ProbeSlotOf(token);
        if (index >= probeCount_) return;

        ProbeSlot& slot = probes_[index];
        if (slot.state.load(std::memory_order_acquire)
                != static_cast<uint32_t>(ProbeState::OUTSTANDING))
            return;

        // The generation is what refuses an answer that arrived after its slot
        // was reclaimed and reused. Without it a straggler would be credited to
        // whichever probe now holds the index.
        if (slot.generation.load(std::memory_order_relaxed) != ProbeGenerationOf(token))
            return;

        // An answer from somewhere other than where the question went is not an
        // answer. The token is unguessable, so this only ever catches a
        // misrouted reply, but the check costs a comparison and the alternative
        // is trusting the source of an unauthenticated packet.
        if (!(slot.addr == from)) return;

        const uint64_t now     = common::MonotonicMicros();
        const uint64_t elapsed = now > slot.sentAtMicros ? now - slot.sentAtMicros : 0;

        // The hold is the far side's, so it comes out: what is left is the path.
        const uint64_t path = elapsed > held ? elapsed - held : 0;

        slot.rttMicros = path > UINT32_MAX ? UINT32_MAX : static_cast<uint32_t>(path);
        slot.state.store(static_cast<uint32_t>(ProbeState::DONE), std::memory_order_release);

        SeedPeerFromProbe(from, path);
    }

    void Socket::SeedPeerFromProbe(const Address& addr, uint64_t rttMicros)
    {
        // Only if a peer is already there. A probe never creates one - that is
        // the guarantee the whole exchange is built around - so this is the
        // narrow case of having measured a path to somebody already known.
        PeerHandle handle = peers_.GetPeer(addr);
        if (handle.Failed()) return;

        Peer* peer = handle.Write();
        if (peer == nullptr) return;

        // SeedFromProbe refuses once acknowledgements have established an
        // average, so this only ever fills the gap before the first one, where
        // the alternative is the configured guess. Nothing else on the estimate
        // is touched: not the windowed minimum, and not the silence stamp,
        // because answering a question is not evidence of a live conversation.
        (void)peer->rtt.SeedFromProbe(rttMicros);
    }

    void Socket::ExpireProbes(uint64_t nowMicros)
    {
        if (probes_ == nullptr) return;

        for (uint32_t i = 0; i < probeCount_; ++i)
        {
            ProbeSlot& slot = probes_[i];
            if (slot.state.load(std::memory_order_acquire)
                    != static_cast<uint32_t>(ProbeState::OUTSTANDING))
                continue;

            if (nowMicros <= slot.sentAtMicros) continue;
            if (nowMicros - slot.sentAtMicros < internal::PROBE_TIMEOUT_MICROS_DEFAULT)
                continue;

            // A round trip of zero is what a timeout reads as. Nothing is
            // retried here: the caller asked one question and is told it went
            // unanswered, which is the only thing this layer can honestly say.
            slot.rttMicros = 0;
            slot.state.store(static_cast<uint32_t>(ProbeState::DONE),
                             std::memory_order_release);
        }
    }

    uint32_t Socket::PollProbes(ProbeResult* out, uint32_t max)
    {
        if (out == nullptr || max == 0 || probes_ == nullptr) return 0;

        uint32_t filled = 0;
        for (uint32_t i = 0; i < probeCount_ && filled < max; ++i)
        {
            ProbeSlot& slot = probes_[i];

            // Claimed by exchange rather than by load-then-store, so two
            // threads draining at once cannot both take the same result and
            // report it twice. The loser sees a state that is no longer DONE
            // and walks on.
            uint32_t expected = static_cast<uint32_t>(ProbeState::DONE);
            if (!slot.state.compare_exchange_strong(
                    expected, static_cast<uint32_t>(ProbeState::CLAIMING),
                    std::memory_order_acq_rel, std::memory_order_relaxed))
                continue;

            out[filled].address   = slot.addr;
            out[filled].rttMicros = slot.rttMicros;
            ++filled;

            // Freed last, so nothing claims the slot while its fields are still
            // being copied out.
            slot.state.store(static_cast<uint32_t>(ProbeState::FREE),
                             std::memory_order_release);
        }
        return filled;
    }
}
