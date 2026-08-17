/* The C API header has to be valid C, which is the one thing every test of it
   written in C++ cannot show. This translation unit exists to be compiled by
   the C compiler and nothing else: it is never linked and never run, so a
   construct that only C++ accepts breaks the build here rather than in the
   first binding somebody writes.

   Everything below is a compile-time use. It reads the table type, the structs
   a binding retypes by hand, the enums, and the sizes, because a header can be
   valid C in its declarations and still contain a definition that is not. */
#include <flux/c/flux_api_v1.h>

#include <stddef.h>

/* The sizes have to be usable where C requires a constant expression, which is
   stricter than being merely parseable. */
static const char kIdentityIsAFixedSize[FLUX_IDENTITY_SIZE];
static const char kCertIsAFixedSize[FLUX_CERT_SIZE];
static const char kTagIsAFixedSize[FLUX_TAG_SIZE];
static const char kNoteIsAFixedSize[FLUX_RESUME_NOTE_BYTES];
static const char kSafePayloadIsPositive[FLUX_SAFE_PAYLOAD_BYTES];

/* Every struct a binding declares for itself, so a member that C cannot name
   fails here. Offsets are taken because that is what LayoutCheck is compared
   against, and offsetof needs a complete type. */
static const size_t kConfigOffsets[] = {
    offsetof(FluxConfig, flows),
    offsetof(FluxConfig, timers),
    offsetof(FluxConfig, liveness),
    offsetof(FluxConfig, events),
    offsetof(FluxConfig, knock),
    offsetof(FluxConfig, port),
    offsetof(FluxConfig, identity),
    offsetof(FluxConfig, keepResumeNotes),
    offsetof(FluxConfig, resumeNoteSeconds),
    offsetof(FluxConfig, identityHistory),
    offsetof(FluxConfig, trustedCertCount),
    offsetof(FluxConfig, rotateAfterBytes),
};

static const size_t kStructSizes[] = {
    sizeof(FluxConfig),      sizeof(FluxFlowsConfig),  sizeof(FluxTimersConfig),
    sizeof(FluxLivenessConfig), sizeof(FluxEventsConfig), sizeof(FluxKnockConfig),
    sizeof(FluxLayout),      sizeof(FluxMessage),      sizeof(FluxPacketInfo),
    sizeof(FluxTransferView), sizeof(FluxApiV1),
};

/* The handle and error typedefs, and the bit macros, used as C would use them. */
static const FluxEventBits kWatched =
      FLUX_EVENT_PEER_ESTABLISHED
    | FLUX_EVENT_PEER_KNOCKED
    | FLUX_EVENT_PEER_STALE_IDENTITY
    | FLUX_EVENT_PEER_CERT_MISMATCH
    | FLUX_EVENT_RESUME_NOTE_RECEIVED;

static const FluxError kCodes[] = {
    FLUX_OK, FLUX_ERR_INVALID_PARAM, FLUX_ERR_NOT_FOUND, FLUX_ERR_ALREADY_PENDING,
};

/* The getter's declaration, and the table reached through it, as a binding
   does it. Not called: this file is compiled, never linked. */
static const FluxApiV1* TableShape(void)
{
    const FluxApiV1* api = (const FluxApiV1*)flux_get_api(1);
    FluxPeer   peer   = FLUX_NONE;
    FluxFlow   flow   = FLUX_NONE;
    FluxPacket packet = FLUX_NONE;
    (void)peer;
    (void)flow;
    (void)packet;
    (void)kIdentityIsAFixedSize;
    (void)kCertIsAFixedSize;
    (void)kTagIsAFixedSize;
    (void)kNoteIsAFixedSize;
    (void)kSafePayloadIsPositive;
    (void)kConfigOffsets;
    (void)kStructSizes;
    (void)kWatched;
    (void)kCodes;
    return api;
}

const void* flux_c_header_check(void);
const void* flux_c_header_check(void)
{
    return (const void*)TableShape();
}
