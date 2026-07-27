#pragma once

#include <cstdio>           
#include <cstring>          
#include <string_view>      
#include <common/error.h>   
#include <common/log.h>
#include <common/result.h>  
#include <common/log.h>     
#include <common/platform.h>

namespace bcp::flux
{
    [[nodiscard]] inline common::Result<sockaddr_storage> ResolveAddress(const char* host, uint16_t port)
    {
                if (!host) {
                return common::Result<sockaddr_storage>::Fail(common::Error::InvalidParam);
            }
            sockaddr_storage result{};

            // Try IPv4 string parse first
            {
                sockaddr_in addr4{};
                if (inet_pton(AF_INET, host, &addr4.sin_addr) == 1) {
                    sockaddr_in6* out = reinterpret_cast<sockaddr_in6*>(&result);
                    out->sin6_family = AF_INET6;
                    out->sin6_port = htons(port);
                    std::memset(&out->sin6_addr, 0, sizeof(out->sin6_addr));
                    out->sin6_addr.s6_addr[10] = 0xFF;
                    out->sin6_addr.s6_addr[11] = 0xFF;
                    std::memcpy(&out->sin6_addr.s6_addr[12], &addr4.sin_addr, sizeof(addr4.sin_addr));
                    return common::Result<sockaddr_storage>::Success(result);
                }
            }

            // Try IPv6 string parse
            {
                sockaddr_in6 addr6{};
                if (inet_pton(AF_INET6, host, &addr6.sin6_addr) == 1) {
                    sockaddr_in6* out = reinterpret_cast<sockaddr_in6*>(&result);
                    out->sin6_family = AF_INET6;
                    out->sin6_port = htons(port);
                    std::memcpy(&out->sin6_addr, &addr6.sin6_addr, sizeof(addr6.sin6_addr));
                    return common::Result<sockaddr_storage>::Success(result);
                }
            }        

            // Fallback to DNS resolution
            addrinfo hints{};
            hints.ai_family = AF_INET6; // IPv6 results (IPv4-mapped if dual stack)
            hints.ai_socktype = SOCK_DGRAM; // Datagram socket
            hints.ai_protocol = IPPROTO_UDP; // UDP protocol
            hints.ai_flags = AI_V4MAPPED | AI_ALL; // Include IPv4-mapped addresses if dual stack
            
            char portStr[8];
            snprintf(portStr, sizeof(portStr), "%u", port);
            addrinfo* dnsResult = nullptr;
            int status = getaddrinfo(host, portStr, &hints, &dnsResult);
            if (status != 0) {
                return common::Result<sockaddr_storage>::Fail(common::Error::ResolveFailed);
            }

            std::memcpy(&result, dnsResult->ai_addr, dnsResult->ai_addrlen);
            freeaddrinfo(dnsResult);

            return common::Result<sockaddr_storage>::Success(result);
    }

    /** Hashable wrapper around sockaddr_storage for use as a key in unordered_map. */
    struct Address {
        sockaddr_storage addr{};

        Address() { std::memset(&addr, 0, sizeof(addr)); }
        explicit Address(const sockaddr_storage& s) {
            std::memset(&addr, 0, sizeof(addr));
            std::memcpy(&addr, &s, sizeof(sockaddr_storage));
        }

        bool operator==(const Address& other) const {
            if (addr.ss_family != other.addr.ss_family) {
                return false;
            }

            if (addr.ss_family == AF_INET) {
                const sockaddr_in* a,* b;
                a = reinterpret_cast<const sockaddr_in*>(&addr);
                b = reinterpret_cast<const sockaddr_in*>(&other.addr);
                return a->sin_port == b->sin_port &&
                        a->sin_addr.s_addr == b->sin_addr.s_addr;
            }
            else if (addr.ss_family == AF_INET6) {
                const sockaddr_in6* a,* b;
                a = reinterpret_cast<const sockaddr_in6*>(&addr);
                b = reinterpret_cast<const sockaddr_in6*>(&other.addr);

                return a->sin6_port == b->sin6_port &&
                        a->sin6_scope_id == b->sin6_scope_id &&
                        std::memcmp(&a->sin6_addr, &b->sin6_addr, sizeof(in6_addr)) == 0;
            }

            return false;
        }

        operator const sockaddr_storage&() const { return addr; } 

        size_t hash() const {
            uint64_t h = 0xcbf29ce484222325ULL;
            constexpr uint64_t prime = 0x100000001b3ULL;

            auto feed = [&](const void* data, size_t len) {
                const auto* bytes = static_cast<const uint8_t*>(data);
                for (size_t i = 0; i < len; i++) {
                    h ^= bytes[i];
                    h *= prime;
                }
            };

            uint16_t family = addr.ss_family;
            feed(&family, sizeof(family));

            if (addr.ss_family == AF_INET) {
                const auto* s = reinterpret_cast<const sockaddr_in*>(&addr);
                feed(&s->sin_addr.s_addr, sizeof(s->sin_addr.s_addr));
                feed(&s->sin_port, sizeof(s->sin_port));
            } else if (addr.ss_family == AF_INET6) {
                const auto* s = reinterpret_cast<const sockaddr_in6*>(&addr);
                feed(s->sin6_addr.s6_addr, 16);
                feed(&s->sin6_scope_id, sizeof(s->sin6_scope_id));
                feed(&s->sin6_port, sizeof(s->sin6_port));
            }

            return static_cast<size_t>(h);
        }

        const char* ToChar(char* out, size_t cap) const {
            char ip[INET6_ADDRSTRLEN] = {};
            uint16_t port = 0;

            if (addr.ss_family == AF_INET) {
                const auto* s = reinterpret_cast<const sockaddr_in*>(&addr);
                if (!inet_ntop(AF_INET, &s->sin_addr, ip, sizeof(ip))) return nullptr;
                port = ntohs(s->sin_port);
            } else if (addr.ss_family == AF_INET6) {
                const auto* s = reinterpret_cast<const sockaddr_in6*>(&addr);
                if (!inet_ntop(AF_INET6, &s->sin6_addr, ip, sizeof(ip))) return nullptr;
                port = ntohs(s->sin6_port);
            } else {
                return nullptr;
            }

            const int n = std::snprintf(out, cap, "[%s]:%u", ip, port);
            if (n < 0 || static_cast<size_t>(n) >= cap) return nullptr;   // encode error or truncated
            return out;
        }

        bool IsSet() const {
            return addr.ss_family != 0;
        }

        void Print() const {
            char ip[INET6_ADDRSTRLEN] = {};

            if (addr.ss_family == AF_INET) {
                const auto* s = reinterpret_cast<const sockaddr_in*>(&addr);
                inet_ntop(AF_INET, &s->sin_addr, ip, sizeof(ip));
                common::LogF(common::LogLevel::Info, "Address { %s:%u }", ip, ntohs(s->sin_port));
            } else if (addr.ss_family == AF_INET6) {
                const auto* s = reinterpret_cast<const sockaddr_in6*>(&addr);
                inet_ntop(AF_INET6, &s->sin6_addr, ip, sizeof(ip));
                common::LogF(common::LogLevel::Info, "Address { [%s]:%u }", ip, ntohs(s->sin6_port));   // brackets to match the route format
            } else {
                common::LogF(common::LogLevel::Info, "Address { <unset / unknown family %u> }", addr.ss_family);
            }
        }

        /** Creates an address from host and port, resolving as needed.
            Returns an error if resolution fails. */
        static common::Result<Address> From(const char* host, uint16_t port) {
            common::Result<sockaddr_storage> res = ResolveAddress(host, port);
            if (res.isErr()) {
                return common::Result<Address>::Fail(res.error);
            }
            return common::Result<Address>::Success(Address(res.Take()));
        }

        static common::Result<Address> From(std::string_view dest) {
            // Required: [host]:port   (host = IPv4 | IPv6 | hostname; brackets + port mandatory)
            if (dest.empty() || dest.front() != '[') return common::Result<Address>::Fail(common::Error::InvalidParam);
            const size_t close = dest.find(']');
            if (close == std::string_view::npos)     return common::Result<Address>::Fail(common::Error::InvalidParam);

            const std::string_view host = dest.substr(1, close - 1);
            const std::string_view rest = dest.substr(close + 1);
            if (rest.empty() || rest.front() != ':') return common::Result<Address>::Fail(common::Error::InvalidParam);   // need ":port"
            const std::string_view portSv = rest.substr(1);
            if (host.empty() || portSv.empty())      return common::Result<Address>::Fail(common::Error::InvalidParam);

            uint32_t v = 0;
            for (char c : portSv) {
                if (c < '0' || c > '9')  return common::Result<Address>::Fail(common::Error::InvalidParam);
                v = v * 10 + uint32_t(c - '0');
                if (v > 65535)           return common::Result<Address>::Fail(common::Error::InvalidParam);
            }
            const uint16_t port = static_cast<uint16_t>(v);

            char hostBuf[256];                          // null-terminate the host slice for getaddrinfo
            if (host.size() >= sizeof(hostBuf)) return common::Result<Address>::Fail(common::Error::InvalidParam);
            std::memcpy(hostBuf, host.data(), host.size());
            hostBuf[host.size()] = '\0';


            common::Result<sockaddr_storage> res = ResolveAddress(hostBuf, port);
            if (res.isErr()) {
                return common::Result<Address>::Fail(res.error);
            }
            return common::Result<Address>::Success(Address(res.Take()));
        }
    };
}