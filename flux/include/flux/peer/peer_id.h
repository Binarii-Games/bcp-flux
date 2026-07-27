#pragma once

#include <array>
#include <cstdint>

#include <common/crypto/crypto.h>

namespace bcp::flux
{
    /** Self-certifying 256-bit peer id: blake2b(pubkey). Deterministic and
        saltless, so either side can recompute it from a presented public key
        and check the peer owns the id it claims (no registry involved).

        Connectionless protocol, and a peer's address can rotate mid-session
        (NAT rebind, VPN reconnect, network handoff); the id stays stable across
        that, so a packet from an unknown address can still be tied to a known
        peer. Not persistent: the keypair is generated per process, so the id
        lives only as long as the peer's process. Never store one.
    */
    struct BcpId
    {
        std::array<uint8_t, 32> id;

        static BcpId Derive(const common::crypto::PublicKey& pk) noexcept
        {
            BcpId out;
            common::crypto::DeriveId(out.id, pk);
            return out;
        }

        bool operator==(const BcpId& o) const noexcept { return id == o.id; }
        bool operator!=(const BcpId& o) const noexcept { return !(*this == o); }
    };
}
