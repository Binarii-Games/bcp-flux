#include <flux/crypto/identity.h>

#include <common/wire/bytes_reader.h>
#include <common/wire/bytes_writer.h>

namespace bcp::flux
{
    common::Result<Identity> Identity::Generate(const Certificate::IdentityTag& tag)
    {
        Identity id;
        if (!common::crypto::GenerateKeypair(id.secretKey, id.publicKey))
            return common::Result<Identity>::Fail(common::Error::RandomFailed);
        id.tag = tag;
        return common::Result<Identity>::Success(id);
    }

    Certificate Identity::ToCertificate() const
    {
        Certificate cert;
        cert.version     = Certificate::VERSION_PINNED;
        cert.subjectKey  = publicKey;
        cert.identityTag = tag;
        return cert;
    }

    void Identity::Wipe() noexcept
    {
        common::crypto::Wipe(secretKey.data(), secretKey.size());
    }

    bool Identity::Serialize(uint8_t* out, size_t cap) const
    {
        if (cap < FILE_SIZE)
            return false;

        uint16_t written = 0;
        common::BytesWriter w{ .p = out, .l = &written, .r = cap };

        return w.PutBytes(secretKey.data(), secretKey.size())
            && w.PutBytes(tag.data(), tag.size());
    }

    common::Result<Identity> Identity::Parse(const uint8_t* in, size_t len)
    {
        common::BytesReader r{ .p = in, .r = len };

        Identity id;
        if (!r.TakeBytes(id.secretKey.data(), id.secretKey.size()) ||
            !r.TakeBytes(id.tag.data(), id.tag.size()))
            return common::Result<Identity>::Fail(common::Error::InvalidHeader);

        common::crypto::DerivePublicKey(id.publicKey, id.secretKey);
        return common::Result<Identity>::Success(id);
    }
}
