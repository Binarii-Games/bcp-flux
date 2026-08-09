// Two transports wanting the same link at the same time. A Flux transfer and
// an msquic bulk stream each move the same payload through ONE tail-drop
// queue draining at one rate, which is what makes them interact: a sender
// keeping more in flight occupies more of the queue, pushes the other's
// packets toward the drop tail, and inflates the delay both of them measure.
// Two shapers at half rate each would measure nothing.
//
// The link is 50 Mbit with a 40 ms round trip and a 250 KB shared queue. The
// question is not who finishes first, it is how the capacity divides while
// both are running and what that division costs in standing queue and drops.
//
//   link_share_bench [bbr|cubic] [MiB]     defaults to bbr, 100
//
// This bench exists only where msquic does. The build finds libmsquic and
// skips the target otherwise, and the server side runs on a self-signed
// throwaway certificate embedded below, which secures nothing and is not
// meant to.
#include <msquic.h>

#include <flux/socket/socket.h>
#include <flux/address.h>
#include <flux/peer/peer.h>
#include <flux/peer/peer_handle.h>
#include <flux/transfer/transfer.h>

#include "flux_net.h"
#include "udp_raw.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <thread>
#include <vector>

namespace flux   = bcp::flux;
namespace common = bcp::common;

namespace
{
    using Clock = std::chrono::steady_clock;

    uint64_t NowMicros()
    {
        return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
            Clock::now().time_since_epoch()).count());
    }

    constexpr uint64_t LINK_KBIT    = 50000;
    constexpr uint64_t OWD_MICROS   = 20000;
    constexpr uint64_t QUEUE_BYTES  = 250000;
    constexpr size_t   MAX_DATAGRAM = 2048;
    constexpr uint64_t REPORT_MICROS = 250000;

    constexpr uint16_t SHAPER_A_PORT   = 9750;   // flux enters here
    constexpr uint16_t FLUX_SEND_PORT  = 9751;
    constexpr uint16_t FLUX_RECV_PORT  = 9752;
    constexpr uint16_t SHAPER_B_PORT   = 9760;   // quic enters here
    constexpr uint16_t QUIC_SERVER_PORT = 9762;

    constexpr const char* BENCH_CERT_PEM =
        "-----BEGIN CERTIFICATE-----\n"
        "MIIDCzCCAfOgAwIBAgIUNcG7P47uTEwp5uJPbx+XDNfeV+QwDQYJKoZIhvcNAQEL\n"
        "BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MCAXDTI2MDgwOTE2MDY1MVoYDzIxMjYw\n"
        "NzE2MTYwNjUxWjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEB\n"
        "AQUAA4IBDwAwggEKAoIBAQCni2oIBRWKdff3l8NELNmhZWMu40nuW4KzGg+gLkbM\n"
        "EGNexAYcQjedAQuZTEBugoFzlh3ARLuLHJ2WRRCMqblC5MVplMMYM5WWFaLWusBm\n"
        "aUKZYg8D0C09K/T3oTT79REjv0XIMm9/7YON7Q+os8P1HQrznXISqiNpRdhThJFQ\n"
        "Vrc3sp8cnJamKghSJ0FzWcTWRfo/b0oV8GzY1bDN3S0gXmUQCB1SZbI+5ccKw61n\n"
        "sILyoSNYzjvypcX7iAEGAweevg5ve+IQ+uRJcMiI68LHCrXYqipVFsSwN+hbQzUk\n"
        "YUqij2fXx31/VCDQoniy9wZmTSWiTEgVkZeMMNKbZxEbAgMBAAGjUzBRMB0GA1Ud\n"
        "DgQWBBRdST/JfDoOC5DBSE3T21LGznuvZTAfBgNVHSMEGDAWgBRdST/JfDoOC5DB\n"
        "SE3T21LGznuvZTAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBL\n"
        "tF5+BRO1Gpl2vOtTYtSITN3t8eP0aJ9G8+7ZR0/BPuGzagfSY96QLdUyzAHI3hK2\n"
        "AGns5jHY6/9iU3zz9CUsmOYORRq2B8glwb29WP6ekMg9KHv9wcv+4PoxS+kTpFGk\n"
        "tIsw4M88/Y2lcB9+haAnC+GsaC+2VMyB6EB7hq8p+Orfi7k6L4Z5S+HR4HbGMRmO\n"
        "56EUvBHmtqO0NloZNKtOGBa5ie2L7jluY7HsYPHv+5so6QQoSkGBPstueCp+c41h\n"
        "MSsY5YSx7+N3dNXWZNjOJfEsLyHuOZR0YsBVeu9LKSKmVgC5PQAQPFZNGK8k3VZx\n"
        "cdY9k3Ne3kSKwAT4IeNr\n"
        "-----END CERTIFICATE-----\n";

    constexpr const char* BENCH_KEY_PEM =
        "-----BEGIN PRIVATE KEY-----\n"
        "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCni2oIBRWKdff3\n"
        "l8NELNmhZWMu40nuW4KzGg+gLkbMEGNexAYcQjedAQuZTEBugoFzlh3ARLuLHJ2W\n"
        "RRCMqblC5MVplMMYM5WWFaLWusBmaUKZYg8D0C09K/T3oTT79REjv0XIMm9/7YON\n"
        "7Q+os8P1HQrznXISqiNpRdhThJFQVrc3sp8cnJamKghSJ0FzWcTWRfo/b0oV8GzY\n"
        "1bDN3S0gXmUQCB1SZbI+5ccKw61nsILyoSNYzjvypcX7iAEGAweevg5ve+IQ+uRJ\n"
        "cMiI68LHCrXYqipVFsSwN+hbQzUkYUqij2fXx31/VCDQoniy9wZmTSWiTEgVkZeM\n"
        "MNKbZxEbAgMBAAECggEAERTIExg9mXesd6wbxsQRzgARrBKVE3115j+Wbzy4kA5t\n"
        "qxguDUx88f9MyOy6tumMPBYGY3c+bZDVyh+xb73P+u9q5vg5Kar8qaf8CYtRmT9L\n"
        "AGs8X6WmLxHfsC1ZwwQ5opzaBu6Jao/y9RHBom/tXvx+hNa87gU1hgKOavldfUSn\n"
        "tzBs1P8PbBvA6IYHB4YpefmXUOkw9AzWl1kMaLE5zu+Wsisj7x96n9mmz6D5t87o\n"
        "2bnlUGBqoS+3RM1ae8LdhTd7XBne8Ae/c8WuVqNjh2HLgAvbJmIPcqNw0ulOK9i4\n"
        "K30ApmbLdnuJe1bm8i+G8wJKpVaW8jhi+PSSUoFkMQKBgQDXd+1AqvLwJwXyq67j\n"
        "yW7oW6z/Of3nJ9JH4ftljkx2L9cCiSGkOUvXNcqOw4DpmhI3jNdS9srbvZoXFeJM\n"
        "cWHytlnHIhzH2HZRNsKMk1kLuVC6vOcjEDosH04R1724T1r+mM/e3QhnSbFIBbZf\n"
        "x7nkMCOwOzOCi4xnEFR7yod4KwKBgQDHD6vGG4kHStqO1EcmB1wZuEM4kuaTypa8\n"
        "Eg0DSLK88uOfYUz2CEi+TlmDcO+vaKxZlojPvX/+ifnoKGMLwutTKoXbxMor6CVE\n"
        "aXpBin5rxh97LnvtiA7Gjii2wam67zxvZQbGq36WzWaeD5Y0MhV0G6OP0NYhoswS\n"
        "6TCtrCji0QKBgQC39XMBADKz6I1Cd2O0pNjk1shni4qEHVKB/qUVOp17VjLavluT\n"
        "izt9/TX4F2BrkRg2hy+bbIsbetAhH5T6sN7wStFxm2U5Fk1F31vQi0i+IrSTCg7I\n"
        "t+UCoKOVxjz7K/1DWxI2cz3meVs7Y20mby39bUA7CQBcV2pC4AVRP0PTywKBgBq5\n"
        "EdhQjf66n8iY2sxSJJ0XTX7kyauBgObSjYipU8Vl3gThbRGCXzGdFws8OBEWPjzw\n"
        "poEs8WfcYf42ncVQb4MErF+qdXGbgpVCi7UMwJf7SvKgdOaYY1NodjLCoOSFhVl2\n"
        "+IfnMeFQxbvmX8W2C4dAxp5h7L0rO7Y2M+C8wehhAoGAUAK+fQDo5jZp/b1p/kLf\n"
        "xhgxiUd7J8wAZ5kYHjj34oqIcgR5qkcnc/txUaqiw2AtufF8okWV+S5AyG81Eocg\n"
        "H31KKzAFEHaoBWb0NZLo+OgpJobKPIb1cWz80jv/mNlLEngzNAuSNXueClnEyu/M\n"
        "/0Z6QcFBfpa7nABJvhk5B7Q=\n"
        "-----END PRIVATE KEY-----\n";

    bool WriteFile(const char* path, const char* text)
    {
        std::FILE* file = std::fopen(path, "w");
        if (!file) return false;
        std::fputs(text, file);
        std::fclose(file);
        return true;
    }

    int RecvFrom(udp_raw::Socket fd, uint8_t* buffer, int max, sockaddr_storage& from,
                 int& fromLen)
    {
#ifdef _WIN32
        int len = sizeof(from);
        const int n = ::recvfrom(fd, reinterpret_cast<char*>(buffer), max, 0,
                                 reinterpret_cast<sockaddr*>(&from), &len);
        fromLen = len;
        return n;
#else
        socklen_t len = sizeof(from);
        const int n = static_cast<int>(::recvfrom(fd, buffer, static_cast<size_t>(max), 0,
                                                  reinterpret_cast<sockaddr*>(&from), &len));
        fromLen = static_cast<int>(len);
        return n;
#endif
    }

    uint16_t PortOf(const sockaddr_storage& addr)
    {
        if (addr.ss_family == AF_INET6)
            return ntohs(reinterpret_cast<const sockaddr_in6&>(addr).sin6_port);
        return ntohs(reinterpret_cast<const sockaddr_in&>(addr).sin_port);
    }

    // --- The shared bottleneck --------------------------------------------

    struct Sample
    {
        uint64_t tMicros;
        uint64_t fluxBytes;      ///< delivered toward the flux receiver so far
        uint64_t quicBytes;      ///< delivered toward the quic server so far
        uint64_t queueDelayMicros;
    };

    struct ShaperResult
    {
        std::vector<Sample> series;
        uint64_t fluxDrops = 0;
        uint64_t quicDrops = 0;
    };

    /** Both competitors feed one queue per direction. Side is told apart by
        which listen port the packet arrived on, so each has its own endpoints
        and neither knows the other exists. */
    void RunSharedShaper(std::atomic<bool>& stop, ShaperResult& result)
    {
        struct Pending
        {
            uint64_t dueMicros;
            int      side;          ///< 0 flux, 1 quic
            bool     toServer;
            uint16_t len;
            uint8_t  data[MAX_DATAGRAM];
        };
        struct Bottleneck
        {
            std::deque<Pending> line;
            uint64_t linkFreeMicros = 0;
            uint64_t queuedBytes    = 0;
        };

        udp_raw::Socket fd[2] = { udp_raw::MakeBound(SHAPER_A_PORT),
                                  udp_raw::MakeBound(SHAPER_B_PORT) };
        if (udp_raw::Bad(fd[0]) || udp_raw::Bad(fd[1])) return;

        // The quic listener is v4, so its forward leaves the shaper's
        // dual-stack socket as a mapped address.
        const flux::Address serverAddr[2] = {
            flux_net::Loopback(FLUX_RECV_PORT),
            flux::Address::From("::ffff:127.0.0.1", QUIC_SERVER_PORT).Take() };
        const uint16_t serverPort[2] = { FLUX_RECV_PORT, QUIC_SERVER_PORT };
        sockaddr_storage clientAddr[2]{};
        int  clientLen[2]  = { 0, 0 };
        bool haveClient[2] = { false, false };

        const uint64_t microsPerByteQ16 = (8000ull << 16) / LINK_KBIT;

        Bottleneck toServer, toClient;
        uint64_t delivered[2] = { 0, 0 };
        uint64_t dropped[2]   = { 0, 0 };
        uint8_t  buffer[MAX_DATAGRAM];

        const uint64_t startMicros = NowMicros();
        uint64_t nextReport = startMicros + REPORT_MICROS;

        while (!stop.load(std::memory_order_relaxed))
        {
            for (int side = 0; side < 2; ++side)
            {
                for (;;)
                {
                    sockaddr_storage from{};
                    int fromLen = 0;
                    const int n = RecvFrom(fd[side], buffer, sizeof(buffer), from, fromLen);
                    if (n <= 0) break;

                    const bool fromServer = PortOf(from) == serverPort[side];
                    if (!fromServer && !haveClient[side])
                    {
                        clientAddr[side] = from;
                        clientLen[side]  = fromLen;
                        haveClient[side] = true;
                    }

                    Bottleneck& queue = fromServer ? toClient : toServer;
                    const uint64_t len = static_cast<uint64_t>(n);
                    if (queue.queuedBytes + len > QUEUE_BYTES)
                    {
                        if (!fromServer) ++dropped[side];
                        continue;
                    }

                    const uint64_t now       = NowMicros();
                    const uint64_t serialise = (microsPerByteQ16 * len) >> 16;
                    const uint64_t departs   = (now > queue.linkFreeMicros
                                                  ? now : queue.linkFreeMicros) + serialise;
                    queue.linkFreeMicros = departs;
                    queue.queuedBytes   += len;

                    queue.line.push_back(Pending{});
                    Pending& pending = queue.line.back();
                    pending.dueMicros = departs + OWD_MICROS;
                    pending.side      = side;
                    pending.toServer  = !fromServer;
                    pending.len       = static_cast<uint16_t>(len);
                    std::memcpy(pending.data, buffer, len);
                }
            }

            const uint64_t now = NowMicros();
            for (Bottleneck* queue : { &toServer, &toClient })
            {
                while (!queue->line.empty() && queue->line.front().dueMicros <= now)
                {
                    Pending& pending = queue->line.front();
                    if (pending.toServer)
                    {
                        udp_raw::SendTo(fd[pending.side], pending.data, pending.len,
                                        serverAddr[pending.side]);
                        delivered[pending.side] += pending.len;
                    }
                    else if (haveClient[pending.side])
                        ::sendto(fd[pending.side],
                                 reinterpret_cast<const char*>(pending.data), pending.len, 0,
                                 reinterpret_cast<const sockaddr*>(&clientAddr[pending.side]),
                                 clientLen[pending.side]);
                    queue->queuedBytes -= pending.len < queue->queuedBytes
                        ? pending.len : queue->queuedBytes;
                    queue->line.pop_front();
                }
            }

            if (now >= nextReport)
            {
                Sample sample;
                sample.tMicros   = now - startMicros;
                sample.fluxBytes = delivered[0];
                sample.quicBytes = delivered[1];
                sample.queueDelayMicros = (microsPerByteQ16 * toServer.queuedBytes) >> 16;
                result.series.push_back(sample);
                nextReport += REPORT_MICROS;
            }

            std::this_thread::sleep_for(std::chrono::microseconds(100));
        }

        result.fluxDrops = dropped[0];
        result.quicDrops = dropped[1];
        udp_raw::Close(fd[0]);
        udp_raw::Close(fd[1]);
    }

    // --- The msquic side ---------------------------------------------------

    const QUIC_API_TABLE* quicApi = nullptr;
    HQUIC quicServerConfig = nullptr;
    const QUIC_BUFFER ALPN = { sizeof("bulk") - 1, (uint8_t*)"bulk" };

    std::atomic<uint64_t> quicBytesIn{0};
    std::atomic<bool>     quicConnected{false};
    std::atomic<uint32_t> quicInFlight{0};

    QUIC_STATUS QUIC_API QuicServerStream(HQUIC stream, void*, QUIC_STREAM_EVENT* event)
    {
        if (event->Type == QUIC_STREAM_EVENT_RECEIVE)
        {
            uint64_t total = 0;
            for (uint32_t i = 0; i < event->RECEIVE.BufferCount; ++i)
                total += event->RECEIVE.Buffers[i].Length;
            quicBytesIn.fetch_add(total, std::memory_order_relaxed);
        }
        else if (event->Type == QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE)
            quicApi->StreamClose(stream);
        return QUIC_STATUS_SUCCESS;
    }

    QUIC_STATUS QUIC_API QuicServerConn(HQUIC conn, void*, QUIC_CONNECTION_EVENT* event)
    {
        if (event->Type == QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED)
            quicApi->SetCallbackHandler(event->PEER_STREAM_STARTED.Stream,
                                        (void*)QuicServerStream, nullptr);
        else if (event->Type == QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE)
            quicApi->ConnectionClose(conn);
        return QUIC_STATUS_SUCCESS;
    }

    QUIC_STATUS QUIC_API QuicListener(HQUIC, void*, QUIC_LISTENER_EVENT* event)
    {
        if (event->Type == QUIC_LISTENER_EVENT_NEW_CONNECTION)
        {
            quicApi->SetCallbackHandler(event->NEW_CONNECTION.Connection,
                                        (void*)QuicServerConn, nullptr);
            return quicApi->ConnectionSetConfiguration(event->NEW_CONNECTION.Connection,
                                                       quicServerConfig);
        }
        return QUIC_STATUS_SUCCESS;
    }

    QUIC_STATUS QUIC_API QuicClientStream(HQUIC, void*, QUIC_STREAM_EVENT* event)
    {
        if (event->Type == QUIC_STREAM_EVENT_SEND_COMPLETE)
        {
            auto* done = static_cast<QUIC_BUFFER*>(event->SEND_COMPLETE.ClientContext);
            if (done) { delete[] done->Buffer; delete done; }
            quicInFlight.fetch_sub(1, std::memory_order_relaxed);
        }
        return QUIC_STATUS_SUCCESS;
    }

    QUIC_STATUS QUIC_API QuicClientConn(HQUIC, void*, QUIC_CONNECTION_EVENT* event)
    {
        if (event->Type == QUIC_CONNECTION_EVENT_CONNECTED) quicConnected.store(true);
        return QUIC_STATUS_SUCCESS;
    }

    void FillQuicSettings(QUIC_SETTINGS& settings, bool useBbr)
    {
        settings.IdleTimeoutMs = 60000;               settings.IsSet.IdleTimeoutMs = TRUE;
        settings.PeerBidiStreamCount = 8;             settings.IsSet.PeerBidiStreamCount = TRUE;
        // Wide open, so the bottleneck under test is the link and the
        // controller rather than a receive window.
        settings.StreamRecvWindowDefault = 16u << 20; settings.IsSet.StreamRecvWindowDefault = TRUE;
        settings.ConnFlowControlWindow   = 64u << 20; settings.IsSet.ConnFlowControlWindow = TRUE;
        settings.SendBufferingEnabled = 0;            settings.IsSet.SendBufferingEnabled = TRUE;
        settings.CongestionControlAlgorithm = useBbr
            ? QUIC_CONGESTION_CONTROL_ALGORITHM_BBR
            : QUIC_CONGESTION_CONTROL_ALGORITHM_CUBIC;
        settings.IsSet.CongestionControlAlgorithm = TRUE;
    }

    // --- The flux side -----------------------------------------------------

    struct FluxReceiver
    {
        flux::Socket*         socket = nullptr;
        std::vector<uint8_t>  buffer;
        std::atomic<uint64_t> bytes{0};
        std::atomic<bool>     done{false};
    };

    void OnTransferOffered(void* context, const flux::EventInfo& info)
    {
        if (!info.Has(flux::SocketEvent::TRANSFER_INCOMING)) return;
        FluxReceiver& receiver = *static_cast<FluxReceiver*>(context);
        flux::TransferRequest request =
            receiver.socket->PendingTransfer(info.Flow(), info.Peer());
        if (!request.Valid()) return;
        receiver.buffer.resize(static_cast<size_t>(request.Length()));
        if (request.Allow(receiver.buffer.data()) != common::Error::Ok)
            (void)request.Reject();
    }

    flux::Socket::Config FluxConfig(uint16_t port)
    {
        flux::Socket::Config config{};
        config.type     = flux_net::BACKEND;
        config.port     = port;
        config.maxPeers = 4;
        config.flows.outCount         = 4;
        config.flows.inCount          = 4;
        config.flows.recvGrant        = 0;
        config.flows.transferOutCount = 2;
        config.flows.transferInCount  = 2;
        config.flows.maxTransferBytes = 4ull << 30;
        return config;
    }
}

int main(int argc, char** argv)
{
    const bool useBbr = argc > 1 ? std::strcmp(argv[1], "cubic") != 0 : true;
    const char* rival = useBbr ? "quic bbr" : "quic cubic";
    const uint64_t mib = argc > 2 ? static_cast<uint64_t>(std::atoll(argv[2])) : 100;
    const uint64_t payloadBytes = mib * 1024 * 1024;
    const double floorSeconds =
        static_cast<double>(payloadBytes) * 8.0 / (LINK_KBIT * 1000.0);

    std::printf("link: 50 Mbit, 40 ms round trip, 250 KB shared tail-drop queue\n");
    std::printf("payload: %llu MiB each, flux transfer beside %s, started together\n\n",
                (unsigned long long)mib, rival);
    std::fflush(stdout);

    if (!WriteFile("link_share_cert.pem", BENCH_CERT_PEM)
        || !WriteFile("link_share_key.pem", BENCH_KEY_PEM))
    { std::printf("  could not write the throwaway certificate\n"); return 0; }

    std::atomic<bool> stopShaper{false};
    ShaperResult shaped;
    std::thread shaper(RunSharedShaper, std::ref(stopShaper), std::ref(shaped));

    // The quic pair, server listening beside the shaper, client through it.
    HQUIC registration = nullptr, clientConfig = nullptr;
    HQUIC listener = nullptr, quicConn = nullptr, quicStream = nullptr;
    if (QUIC_FAILED(MsQuicOpen2(&quicApi)))
    { std::printf("  msquic failed to open\n"); return 0; }
    const QUIC_REGISTRATION_CONFIG regConfig = { "share", QUIC_EXECUTION_PROFILE_LOW_LATENCY };
    quicApi->RegistrationOpen(&regConfig, &registration);

    QUIC_SETTINGS settings{};
    FillQuicSettings(settings, useBbr);

    QUIC_CERTIFICATE_FILE certFile{};
    certFile.PrivateKeyFile  = "link_share_key.pem";
    certFile.CertificateFile = "link_share_cert.pem";
    QUIC_CREDENTIAL_CONFIG serverCred{};
    serverCred.Type            = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
    serverCred.CertificateFile = &certFile;
    quicApi->ConfigurationOpen(registration, &ALPN, 1, &settings, sizeof(settings),
                               nullptr, &quicServerConfig);
    if (QUIC_FAILED(quicApi->ConfigurationLoadCredential(quicServerConfig, &serverCred)))
    { std::printf("  msquic refused the certificate, is this an OpenSSL build?\n"); return 0; }

    QUIC_CREDENTIAL_CONFIG clientCred{};
    clientCred.Type  = QUIC_CREDENTIAL_TYPE_NONE;
    clientCred.Flags = QUIC_CREDENTIAL_FLAG_CLIENT
                     | QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
    quicApi->ConfigurationOpen(registration, &ALPN, 1, &settings, sizeof(settings),
                               nullptr, &clientConfig);
    quicApi->ConfigurationLoadCredential(clientConfig, &clientCred);

    quicApi->ListenerOpen(registration, QuicListener, nullptr, &listener);
    QUIC_ADDR listenAddr{};
    QuicAddrSetFamily(&listenAddr, QUIC_ADDRESS_FAMILY_INET);
    QuicAddrSetPort(&listenAddr, QUIC_SERVER_PORT);
    if (QUIC_FAILED(quicApi->ListenerStart(listener, &ALPN, 1, &listenAddr)))
    { std::printf("  msquic listener failed to start\n"); return 0; }

    // The flux pair, receiver beside the shaper, sender through it.
    FluxReceiver state;
    flux::Socket receiver;
    flux::Socket::Config receiverConfig = FluxConfig(FLUX_RECV_PORT);
    receiverConfig.events.hook       = OnTransferOffered;
    receiverConfig.events.context    = &state;
    receiverConfig.events.subscribed = flux::ToBits(flux::SocketEvent::TRANSFER_INCOMING);
    state.socket = &receiver;
    if (receiver.Init(receiverConfig) != common::Error::Ok) return 0;
    flux::Socket sender;
    if (sender.Init(FluxConfig(FLUX_SEND_PORT)) != common::Error::Ok) return 0;

    std::atomic<bool> stopReceiver{false};
    std::thread receiverThread([&]
    {
        flux::PacketSlotHandle inbox[64];
        while (!stopReceiver.load(std::memory_order_relaxed))
        {
            receiver.Update();
            { flux::PollCursor cursor = receiver.Poll(inbox, 64); while (cursor.Next()) {} }
            flux::TransferView finished[2];
            const size_t count = receiver.PollTransfers(finished, 2);
            for (size_t i = 0; i < count; ++i)
            {
                if (!finished[i].Bytes()) continue;
                state.bytes = finished[i].Length();
                (void)receiver.CompleteTransfer(finished[i].Flow(), finished[i].Peer());
                state.done = true;
            }
            receiver.Flush();
        }
        for (auto& handle : inbox) handle = flux::PacketSlotHandle::Invalid();
    });

    // Both sessions come up before either load starts, so the race is between
    // transfers rather than handshakes.
    const flux::Address via = flux_net::Loopback(SHAPER_A_PORT);
    (void)sender.Connect(via);
    {
        flux::PacketSlotHandle inbox[16];
        const auto until = Clock::now() + std::chrono::seconds(10);
        while (Clock::now() < until && !flux_net::Established(sender, via))
        {
            sender.Update();
            { flux::PollCursor cursor = sender.Poll(inbox, 16); while (cursor.Next()) {} }
            sender.Flush();
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        for (auto& handle : inbox) handle = flux::PacketSlotHandle::Invalid();
    }
    quicApi->ConnectionOpen(registration, QuicClientConn, nullptr, &quicConn);
    quicApi->ConnectionStart(quicConn, clientConfig, QUIC_ADDRESS_FAMILY_INET,
                             "127.0.0.1", SHAPER_B_PORT);
    for (int i = 0; i < 10000 && !quicConnected.load(); ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    if (!flux_net::Established(sender, via) || !quicConnected.load())
    {
        std::printf("  a session never came up through the shaper:"
                    " flux %s, quic %s\n",
                    flux_net::Established(sender, via) ? "up" : "down",
                    quicConnected.load() ? "up" : "down");
        stopReceiver = true;
        receiverThread.join();
        stopShaper = true;
        shaper.join();
        sender.Shutdown();
        receiver.Shutdown();
        return 0;
    }

    quicApi->StreamOpen(quicConn, QUIC_STREAM_OPEN_FLAG_NONE, QuicClientStream,
                        nullptr, &quicStream);
    quicApi->StreamStart(quicStream, QUIC_STREAM_START_FLAG_NONE);

    // Both loads, same instant. The quic pump runs on its own thread, the
    // flux pump on this one.
    const auto start    = Clock::now();
    const auto deadline = start + std::chrono::seconds(
        static_cast<int64_t>(floorSeconds * 10.0) + 10);

    double quicSeconds = 0.0;
    std::thread quicPump([&]
    {
        constexpr uint32_t CHUNK = 1000, OUTSTANDING = 4096;
        uint64_t offered = 0;
        while (quicBytesIn.load(std::memory_order_relaxed) < payloadBytes
               && Clock::now() < deadline)
        {
            while (offered < payloadBytes
                   && quicInFlight.load(std::memory_order_relaxed) < OUTSTANDING)
            {
                auto* chunk = new QUIC_BUFFER{ CHUNK, new uint8_t[CHUNK] };
                std::memset(chunk->Buffer, 0x5A, CHUNK);
                quicInFlight.fetch_add(1, std::memory_order_relaxed);
                if (QUIC_FAILED(quicApi->StreamSend(quicStream, chunk, 1,
                                                    QUIC_SEND_FLAG_NONE, chunk)))
                {
                    quicInFlight.fetch_sub(1, std::memory_order_relaxed);
                    delete[] chunk->Buffer; delete chunk;
                    break;
                }
                offered += CHUNK;
            }
            std::this_thread::sleep_for(std::chrono::microseconds(100));
        }
        if (quicBytesIn.load(std::memory_order_relaxed) >= payloadBytes)
            quicSeconds = std::chrono::duration<double>(Clock::now() - start).count();
    });

    double fluxSeconds = 0.0;
    std::vector<uint8_t> payload(static_cast<size_t>(payloadBytes), 0x5A);
    if (sender.SendTransfer(1, via, payload.data(), payloadBytes) == common::Error::Ok)
    {
        flux::PacketSlotHandle inbox[64];
        while (!state.done.load(std::memory_order_relaxed) && Clock::now() < deadline)
        {
            sender.Update();
            { flux::PollCursor cursor = sender.Poll(inbox, 64); while (cursor.Next()) {} }
            flux::TransferView finished[2];
            (void)sender.PollTransfers(finished, 2);
            sender.Flush();
        }
        for (auto& handle : inbox) handle = flux::PacketSlotHandle::Invalid();
        if (state.done.load(std::memory_order_relaxed)
            && state.bytes.load(std::memory_order_relaxed) == payloadBytes)
            fluxSeconds = std::chrono::duration<double>(Clock::now() - start).count();
    }

    quicPump.join();
    stopReceiver = true;
    receiverThread.join();
    stopShaper = true;
    shaper.join();

    // The split, over the window where both were actually sending. Rates per
    // sample interval, an interval counts once both exceed a trickle, and the
    // first second is left out as ramp.
    double fluxMean = 0.0, quicMean = 0.0, queueMean = 0.0;
    uint32_t contended = 0;
    for (size_t i = 5; i < shaped.series.size(); ++i)
    {
        const Sample& previous = shaped.series[i - 1];
        const Sample& current  = shaped.series[i];
        const double dt = static_cast<double>(current.tMicros - previous.tMicros) / 1e6;
        if (dt <= 0.0) continue;
        const double fluxRate = static_cast<double>(current.fluxBytes - previous.fluxBytes)
                              * 8.0 / (dt * 1e6);
        const double quicRate = static_cast<double>(current.quicBytes - previous.quicBytes)
                              * 8.0 / (dt * 1e6);
        if (fluxRate < 0.05 || quicRate < 0.05) continue;
        fluxMean  += fluxRate;
        quicMean  += quicRate;
        queueMean += static_cast<double>(current.queueDelayMicros) / 1000.0;
        ++contended;
    }

    const char* rule = "  +---------------+-----------+-------------+--------------+\n";
    std::printf("%s", rule);
    std::printf("  | sender        |      time |     goodput |  share while |\n");
    std::printf("  |               |           |             |   contended  |\n");
    std::printf("%s", rule);
    if (contended > 0)
    {
        fluxMean  /= contended;
        quicMean  /= contended;
        queueMean /= contended;
        const double total = fluxMean + quicMean;
        auto row = [&](const char* name, double seconds, double share)
        {
            if (seconds > 0.0)
                std::printf("  | %-13s | %6.2f s  | %5.1f Mbit  | %9.1f %%  |\n",
                            name, seconds,
                            static_cast<double>(payloadBytes) * 8.0 / (seconds * 1e6),
                            share);
            else
                std::printf("  | %-13s |    DNF    |      -      | %9.1f %%  |\n",
                            name, share);
        };
        row("flux transfer", fluxSeconds, 100.0 * fluxMean / total);
        row(rival, quicSeconds, 100.0 * quicMean / total);
        std::printf("%s", rule);

        const double jain = (total * total)
            / (2.0 * (fluxMean * fluxMean + quicMean * quicMean));
        std::printf("\n  contended %.0f s, Jain %.3f, queue %.1f ms,"
                    " drops flux %llu, %s %llu\n",
                    contended * (REPORT_MICROS / 1e6), jain, queueMean,
                    (unsigned long long)shaped.fluxDrops, rival,
                    (unsigned long long)shaped.quicDrops);
    }
    else
    {
        std::printf("  the two never ran at the same time, no split to report\n");
        std::printf("%s", rule);
    }

    sender.Shutdown();
    receiver.Shutdown();
    std::remove("link_share_cert.pem");
    std::remove("link_share_key.pem");
    return 0;
}
