// PeerTable, the whole lifecycle and its documented edges. Register a peer and
// find it by address; remove it and it is gone; bind an id later and find it by
// that too; rebind its address (the operation an address migration completes)
// and it moves without losing its slot. The refusals matter as much as the
// successes: a duplicate address, a full pool, and a rebind onto an occupied
// address are all rejected, and the tag index maps many-to-many.
//
// A PeerHandle holds the peer's read lock, and a table mutation waits on that
// lock, so every handle here is dropped (its scope closed) before the next
// mutation — never held across one.
#include <flux/peer/peer_table.h>
#include <flux/peer/peer_handle.h>
#include <flux/peer/peer_id.h>
#include <flux/peer/peer.h>
#include <flux/address.h>

#include "harness.h"

#include <cstdint>

using bcp::flux::Address;
using bcp::flux::BcpId;
using bcp::flux::PeerHandle;
using bcp::flux::PeerTag;
using bcp::flux::PeerTable;
using bcp::common::Error;

static Address AddressAt(uint16_t port)
{
    return Address::From("::1", port).Take();
}

static BcpId IdOf(uint8_t seed)
{
    BcpId id{};
    for (size_t i = 0; i < id.id.size(); ++i) id.id[i] = static_cast<uint8_t>(seed + i);
    return id;
}

// A registered peer is found by its address; removing it makes it a stranger.
static void register_lookup_remove()
{
    PeerTable table;
    CHECK(table.Init(16) == Error::Ok);

    const Address addr = AddressAt(5000);
    uint32_t slot = 0;
    CHECK(table.RegisterPeer(addr, nullptr, slot) == Error::Ok);
    CHECK(table.GetPeerCount() == 1);

    {
        PeerHandle found = table.GetPeer(addr);
        CHECK(!found.Failed());
        CHECK(found.GetSlotIndex() == slot);
    }

    CHECK(table.RemovePeer(addr) == Error::Ok);
    CHECK(table.GetPeerCount() == 0);
    {
        PeerHandle gone = table.GetPeer(addr);
        CHECK(gone.Failed());
    }
}

// Registering an address that is already live is refused and inserts nothing.
static void duplicate_address_refused()
{
    PeerTable table;
    CHECK(table.Init(16) == Error::Ok);

    const Address addr = AddressAt(5100);
    uint32_t first = 0, second = 0;
    CHECK(table.RegisterPeer(addr, nullptr, first) == Error::Ok);
    CHECK(table.RegisterPeer(addr, nullptr, second) == Error::AlreadyPending);
    CHECK(table.GetPeerCount() == 1);
}

// The pool caps live peers: filling it to capacity succeeds, one more does not.
static void full_pool_refused()
{
    PeerTable table;
    CHECK(table.Init(8) == Error::Ok);
    uint32_t capacity = table.GetCapacity();

    for (uint32_t i = 0; i < capacity; ++i)
    {
        uint32_t slot = 0;
        CHECK(table.RegisterPeer(AddressAt(static_cast<uint16_t>(5200 + i)), nullptr, slot) == Error::Ok);
    }
    uint32_t overflow = 0;
    CHECK(table.RegisterPeer(AddressAt(static_cast<uint16_t>(5200 + capacity)), nullptr, overflow)
          == Error::MaxPeersReached);
    CHECK(table.GetPeerCount() == capacity);
}

// An id bound after registration finds the same peer the address does.
static void bind_id_finds_the_same_peer()
{
    PeerTable table;
    CHECK(table.Init(16) == Error::Ok);

    const Address addr = AddressAt(5300);
    const BcpId   id   = IdOf(0x40);
    uint32_t slot = 0;
    CHECK(table.RegisterPeer(addr, nullptr, slot) == Error::Ok);

    {
        PeerHandle byId = table.GetPeer(id);
        CHECK(byId.Failed());   // id not bound yet
    }

    CHECK(table.BindId(slot, id) == Error::Ok);
    {
        PeerHandle byAddr = table.GetPeer(addr);
        PeerHandle byId   = table.GetPeer(id);
        CHECK(!byAddr.Failed() && !byId.Failed());
        CHECK(byAddr.GetSlotIndex() == byId.GetSlotIndex());   // one peer, two keys
    }
}

// Rebinding moves a live peer to a new address (same slot) and refuses to
// collide with an address another peer already holds.
static void rebind_moves_and_refuses_collision()
{
    PeerTable table;
    CHECK(table.Init(16) == Error::Ok);

    const Address oldAddr = AddressAt(5400);
    const Address newAddr = AddressAt(5401);
    uint32_t slot = 0;
    CHECK(table.RegisterPeer(oldAddr, nullptr, slot) == Error::Ok);

    CHECK(table.UpdateAddress(slot, newAddr) == Error::Ok);
    {
        PeerHandle atNew = table.GetPeer(newAddr);
        PeerHandle atOld = table.GetPeer(oldAddr);
        CHECK(!atNew.Failed() && atNew.GetSlotIndex() == slot);   // moved, same slot
        CHECK(atOld.Failed());                                    // old address gone
    }

    // A second peer, and a rebind onto its address must be refused.
    const Address otherAddr = AddressAt(5402);
    uint32_t otherSlot = 0;
    CHECK(table.RegisterPeer(otherAddr, nullptr, otherSlot) == Error::Ok);
    CHECK(table.UpdateAddress(slot, otherAddr) == Error::AlreadyPending);
    {
        PeerHandle stillOther = table.GetPeer(otherAddr);
        CHECK(!stillOther.Failed() && stillOther.GetSlotIndex() == otherSlot);
    }
}

// The tag index is many-to-many: two peers can share a tag, one peer can hold
// several, and the all-zero tag is reserved. GetPeersByTag returns every
// holder; unbinding one leaves the other.
static void tag_index_is_multi_value()
{
    PeerTable table;
    CHECK(table.Init(16) == Error::Ok);

    uint32_t slotA = 0, slotB = 0;
    CHECK(table.RegisterPeer(AddressAt(5500), nullptr, slotA) == Error::Ok);
    CHECK(table.RegisterPeer(AddressAt(5501), nullptr, slotB) == Error::Ok);

    const PeerTag shared{1, 2, 3, 4};
    const PeerTag zero{0, 0, 0, 0};

    CHECK(table.BindTag(slotA, zero) == Error::InvalidParam);   // reserved marker
    CHECK(table.BindTag(slotA, shared) == Error::Ok);
    CHECK(table.BindTag(slotB, shared) == Error::Ok);           // clash: both hold it

    {
        PeerHandle holders[4];
        uint32_t total = table.GetPeersByTag(shared, holders, 4);
        CHECK(total == 2);
    }

    CHECK(table.UnbindTag(slotA, shared) == Error::Ok);
    {
        PeerHandle holders[4];
        uint32_t total = table.GetPeersByTag(shared, holders, 4);
        CHECK(total == 1);   // only slotB still holds it
    }
}

int main()
{
    register_lookup_remove();
    duplicate_address_refused();
    full_pool_refused();
    bind_id_finds_the_same_peer();
    rebind_moves_and_refuses_collision();
    tag_index_is_multi_value();
    return test::report();
}
