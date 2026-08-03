#pragma once

#include <cstdint>

namespace bcp::common {
    /** What a call can go wrong with, across every library in the set.

        The names describe the failure and never the caller. This lives in
        `common`, so a code naming a packet, a peer or a handshake would put a
        transport's vocabulary in a library meant to know nothing about one. A
        transport returns "not found" and the reader knows from the call that
        the thing not found was a peer.

        Grouped by numeric range so a group can grow without renumbering, and
        every code has a string below. */
    enum class Error : uint8_t {
        Ok               = 0,

        // General
        NotInitialized   = 1,
        InvalidParam     = 2,
        InvalidState     = 3,
        LimitReached     = 4,
        ResolveFailed    = 5,
        NotImplemented   = 6,
        RandomFailed     = 7,
        AlreadyInUse     = 8,
        NotFound         = 9,

        // Platform
        IoFailed         = 10,
        BindFailed       = 11,
        SendFailed       = 12,

        // Memory
        AllocFailed      = 20,
        PoolExhausted    = 21,
        BufferFull       = 22,
        TooLarge         = 23,

        // Data
        Malformed        = 30,
        NotAuthenticated = 31,

        // Work already under way
        AlreadyPending   = 40,
        TooManyPending   = 41,
    };

    inline const char* ErrorToString(Error err) {
        switch (err) {
            case Error::Ok:               return "Ok";
            case Error::NotInitialized:   return "Not initialized";
            case Error::InvalidParam:     return "Invalid parameter";
            case Error::InvalidState:     return "Invalid state";
            case Error::LimitReached:     return "Limit reached";
            case Error::ResolveFailed:    return "Resolve failed";
            case Error::NotImplemented:   return "Not implemented";
            case Error::RandomFailed:     return "Random generation failed";
            case Error::AlreadyInUse:     return "Already in use";
            case Error::NotFound:         return "Not found";
            case Error::IoFailed:         return "I/O failed";
            case Error::BindFailed:       return "Bind failed";
            case Error::SendFailed:       return "Send failed";
            case Error::AllocFailed:      return "Allocation failed";
            case Error::PoolExhausted:    return "Pool exhausted";
            case Error::BufferFull:       return "Buffer full";
            case Error::TooLarge:         return "Too large";
            case Error::Malformed:        return "Malformed";
            case Error::NotAuthenticated: return "Not authenticated";
            case Error::AlreadyPending:   return "Already pending";
            case Error::TooManyPending:   return "Too many pending";
            default:                      return "Unknown error";
        }
    }
}
