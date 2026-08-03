#pragma once

/** The operating system's socket headers, in one place.

    These live here rather than in `common` because `common` has no sockets and
    nothing in it needs them. Putting them there meant that anything wanting a
    cache-line size pulled in the whole networking stack, and on Windows linked
    Winsock, which is a transport's dependency arriving through a library that
    is meant to know nothing about transports.

    Include this from anything that names a `sockaddr`, resolves a host, or
    talks to a socket. Nothing else needs it. */

#ifdef _WIN32
    #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN   // avoid winsock1 clashing with winsock2
    #endif
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")   // MSVC: auto-links winsock, one less linker flag
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>               // inet_ntop / inet_pton
    #include <netdb.h>                   // getaddrinfo / addrinfo (ws2tcpip.h covers these on Windows)
#endif
