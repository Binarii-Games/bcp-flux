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
        (NAT rebind, VPN reconnect, network handoff). The id follows the key
        rather than the address, so a packet from an unknown address can still
        be tied to a known peer. Its lifetime follows the keypair: a socket
        given an identity in Config keeps the same id across runs, and one
        that generates its own keeps it only for that process.
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
