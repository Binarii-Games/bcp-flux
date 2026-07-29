// Error codes and their human-readable strings for Flux.
#pragma once

#include <cstdint>

namespace bcp::common {
    enum class Error : uint8_t {
        Ok              = 0,

        // General
        NotInitialized  = 1,
        InvalidParam    = 2,
        InvalidState    = 3,
        LimitReached    = 4,
        ResolveFailed   = 5,
        NotImplemented  = 6,
        RandomFailed    = 7,
        AlreadyInUse    = 8,

        // Socket
        SocketFailed    = 10,
        BindFailed      = 11,
        SendFailed      = 12,
        BufferFull      = 13,
        PacketTooLarge  = 14,

        // Memory
        AllocFailed     = 20,
        PoolExhausted   = 21,

        // Protocol
        InvalidHeader   = 30,
        InvalidChannel  = 31,
        DuplicatePacket = 32,
        OutOfWindow     = 33,
        DecryptFailed   = 34,

        // Peer
        PeerNotFound    = 40,
        PeerTimedOut    = 41,
        MaxPeersReached = 42,

        // Handshake
        HandshakeFailed  = 50,
        ChallengeFailed  = 51,
        AlreadyPending   = 52,
        NotAuthenticated = 53,

        // Retransmit
        StoreFailed     = 60,
        RingFull        = 61,
        TooManyPending  = 62,

        // Transport
        NoEndpoints     = 70,
        EndpointFull    = 71,

        // Bon
        FieldOverflow   = 80,
        DataOverflow    = 81,
        TypeMismatch    = 82,
        FieldNotFound   = 83,
    };

    inline const char* ErrorToString(Error err) {
        switch (err) {
            case Error::Ok:              return "Ok";
            case Error::NotInitialized:  return "Not initialized";
            case Error::InvalidParam:    return "Invalid parameter";
            case Error::InvalidState:    return "Invalid state";
            case Error::LimitReached:    return "Limit reached";
            case Error::ResolveFailed:   return "Resolve failed";
            case Error::NotImplemented:  return "Not implemented";
            case Error::RandomFailed:    return "Random generation failed";
            case Error::AlreadyInUse:    return "Already in use";
            case Error::SocketFailed:    return "Socket creation failed";
            case Error::BindFailed:      return "Bind failed";
            case Error::SendFailed:      return "Send failed";
            case Error::BufferFull:      return "Buffer full";
            case Error::PacketTooLarge:  return "Packet too large";
            case Error::AllocFailed:     return "Allocation failed";
            case Error::PoolExhausted:   return "Pool exhausted";
            case Error::InvalidHeader:   return "Invalid header";
            case Error::InvalidChannel:  return "Invalid channel";
            case Error::DuplicatePacket: return "Duplicate packet";
            case Error::OutOfWindow:     return "Out of window";
            case Error::DecryptFailed:   return "Decrypt failed";
            case Error::PeerNotFound:    return "Peer not found";
            case Error::PeerTimedOut:    return "Peer timed out";
            case Error::MaxPeersReached: return "Max peers reached";
            case Error::HandshakeFailed: return "Handshake failed";
            case Error::ChallengeFailed: return "Challenge failed";
            case Error::AlreadyPending:  return "Already pending";
            case Error::NotAuthenticated: return "Peer not authenticated";
            case Error::StoreFailed:     return "Store failed";
            case Error::RingFull:        return "Ring full";
            case Error::TooManyPending:  return "Too many pending";
            case Error::NoEndpoints:     return "No endpoints";
            case Error::EndpointFull:    return "Endpoint full";
            case Error::FieldOverflow:   return "Field overflow";
            case Error::DataOverflow:    return "Data overflow";
            case Error::TypeMismatch:    return "Type mismatch";
            case Error::FieldNotFound:   return "Field not found";
            default:                     return "Unknown error";
        }
    }
}