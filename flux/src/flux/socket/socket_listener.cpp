#include <flux/socket/socket_listener.h>
#include <flux/internal/constants.h>

#include <common/result.h>

namespace bcp::flux
{
    common::Error SocketListener::Init(ISocketKernel* source)
    {
        sockKernel_ = source;
        return common::Error::Ok;
    }

    uint32_t SocketListener::Poll(PacketSlotHandle* out, size_t max)
    {
        common::Result<uint32_t> res = sockKernel_->ReceiveFrom(out, static_cast<uint32_t>(max));
        if (res.isErr()) return 0;

        // uint32_t got = res.Take();
        // uint32_t pushed = processingQ.PushBatch(recvBuf, got);
        // if (pushed < got)
        // {
        //     uint32_t missCount = got - pushed;
        //     sockKernel_->ReleasePacket(reinterpret_cast<uint8_t**>(&recvBuf[pushed]), missCount);
        // }
        return res.Take();
    }
}