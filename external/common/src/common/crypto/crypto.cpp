#include <common/crypto/crypto.h>



namespace bcp::common
{


    bool SecureRandom(uint8_t* out, size_t len) noexcept
    {
        // crypto::RandomBytes already carries the per-platform RNG selection
        // (BCryptGenRandom / getentropy / getrandom); one home for that logic.
        return crypto::RandomBytes(out, len);
    }
}