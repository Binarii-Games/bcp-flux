#pragma once

#include <cstddef>
#include <cstdint>

#include <common/error.h>

namespace bcp::flux
{
    /** The built-in persistence for resumption notes: one file per issuer
        identity inside a directory the application names, written when a note
        arrives and read back at Init. This is the only code in flux that
        touches a filesystem, and it runs only when Config names a directory.

        Writes go to a temporary name and rename into place, so a crash
        mid-write leaves the previous file, never a torn one. Files are
        created owner-only where the platform expresses that. Nothing here
        validates content: a stale, truncated, or foreign file fails the
        bundle decode or the unseal at resume, and either way costs one slow
        connection, so the store can stay this small. */
    class TicketFileStore
    {
    public:
        static constexpr size_t MAX_DIR = 4096;

        /** Remembers the directory. No I/O happens here, so a bad path shows
            up at the first Save or LoadAll rather than failing Init.
            InvalidParam when the path is null, empty, or too long. */
        [[nodiscard]] common::Error Init(const char* directory);

        bool Active() const { return dir_[0] != '\0'; }

        /** Writes the bundle as <dir>/<hex issuerId>.ftk, atomically. A
            failure is silent by design: persistence is an optimization, and
            the note is already live in memory. */
        void Save(const uint8_t issuerId[32], const uint8_t* bundle, size_t len) noexcept;

        /** Removes the issuer's file, for a note that expired or was
            replaced by one from a different issuer taking its slot. */
        void Remove(const uint8_t issuerId[32]) noexcept;

        /** Feeds every .ftk file's content to the sink. A sink returning
            false refuses the bundle (expired, corrupt, foreign) and the file
            is deleted, which is the purge half of loading. */
        void LoadAll(void* context,
                     bool (*sink)(void* context, const uint8_t* bundle, size_t len));

    private:
        char dir_[MAX_DIR] = {};
    };
}
