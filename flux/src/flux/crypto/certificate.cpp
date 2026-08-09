#include <flux/crypto/certificate.h>

#include <common/wire/bytes_reader.h>
#include <common/wire/bytes_writer.h>

namespace bcp::flux
{
    bool Certificate::Serialize(uint8_t* out, size_t cap) const
    {
        if (cap < PINNED_SIZE)
            return false;

        uint16_t written = 0;
        common::BytesWriter w{ .p = out, .written = &written, .r = cap };

        return w.PutU8(version)
            && w.PutBytes(subjectKey.data(), subjectKey.size())
            && w.PutBytes(identityTag.data(), identityTag.size());
    }

    common::Result<Certificate> Certificate::Parse(const uint8_t* in, size_t len)
    {
        common::BytesReader r{ .p = in, .r = len };

        uint8_t ver = 0;
        if (!r.TakeU8(ver) || ver != VERSION_PINNED)
            return common::Result<Certificate>::Fail(common::Error::Malformed);

        Certificate cert;
        cert.version = ver;
        if (!r.TakeBytes(cert.subjectKey.data(), cert.subjectKey.size()) ||
            !r.TakeBytes(cert.identityTag.data(), cert.identityTag.size()))
            return common::Result<Certificate>::Fail(common::Error::Malformed);

        return common::Result<Certificate>::Success(cert);
    }
}
