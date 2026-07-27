#include <utility>
#include <flux/socket/i_socket_kernel.h>
#include <flux/wire/packet_builder.h>
#include <flux/socket/packet_slot.h>

namespace bcp::flux
{
    common::Result<PacketSlotWriter> ISocketKernel::Write()
    {
        uint32_t slotIdx = sendSlotPool_.Acquire();
        if ( slotIdx == common::collections::SlotPool::INVALID) 
        {
            return common::Result<PacketSlotWriter>::Fail(common::Error::PoolExhausted);
        }

        PacketSlotHandle handle{slotIdx, &sendSlotPool_};
        return common::Result<PacketSlotWriter>::Success(PacketSlotWriter{std::move(handle)});
    }
}