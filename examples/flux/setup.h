#pragma once

// Platform setup shared by the examples: which UDP backend to use, and getting
// Winsock up on Windows. It lives here so each example reads as the thing it
// demonstrates instead of as boilerplate — the same job tests/flux_net.h does
// for the test suite.

#include <common/platform.h>   // OS socket headers, incl. Winsock on Windows

#include <flux/socket/socket.h>

namespace examples
{
#ifdef _WIN32
    inline constexpr bcp::flux::Socket::BackendType BACKEND =
        bcp::flux::Socket::BackendType::STD_WIN;

    struct WinsockBoot { WinsockBoot() { WSADATA data; WSAStartup(MAKEWORD(2, 2), &data); } };
    inline WinsockBoot g_winsockBoot;
#else
    inline constexpr bcp::flux::Socket::BackendType BACKEND =
        bcp::flux::Socket::BackendType::STD_UNX;
#endif
}
