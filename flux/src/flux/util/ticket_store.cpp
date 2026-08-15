#include <flux/util/ticket_store.h>

#include <cstdio>
#include <cstring>

#include <flux/ticket/ticket_table.h>

#ifdef _WIN32
    #ifndef WIN32_LEAN_AND_MEAN
        #define WIN32_LEAN_AND_MEAN
    #endif
    #include <windows.h>
#else
    #include <dirent.h>
    #include <fcntl.h>
    #include <sys/stat.h>
    #include <unistd.h>
#endif

namespace bcp::flux
{
    static constexpr char SUFFIX[] = ".ftk";
    static constexpr size_t HEX_ID = 64;   // 32 identity bytes as hex

    static void HexId(const uint8_t id[32], char out[HEX_ID + 1])
    {
        static constexpr char DIGITS[] = "0123456789abcdef";
        for (size_t i = 0; i < 32; ++i)
        {
            out[i * 2]     = DIGITS[id[i] >> 4];
            out[i * 2 + 1] = DIGITS[id[i] & 0x0F];
        }
        out[HEX_ID] = '\0';
    }

    common::Error TicketFileStore::Init(const char* directory)
    {
        if (!directory || directory[0] == '\0') return common::Error::InvalidParam;
        const size_t len = std::strlen(directory);
        // Room for the path, a separator, the hex name, the suffix, and a
        // ".tmp" behind the suffix during a write.
        if (len + 1 + HEX_ID + sizeof(SUFFIX) + 4 >= sizeof(dir_))
            return common::Error::InvalidParam;
        std::memcpy(dir_, directory, len + 1);
        return common::Error::Ok;
    }

    void TicketFileStore::Save(const uint8_t issuerId[32],
                               const uint8_t* bundle, size_t len) noexcept
    {
        if (!Active() || !bundle || len == 0) return;

        char name[HEX_ID + 1];
        HexId(issuerId, name);
        char finalPath[MAX_DIR];
        char tmpPath[MAX_DIR];
        std::snprintf(finalPath, sizeof(finalPath), "%s/%s%s", dir_, name, SUFFIX);
        std::snprintf(tmpPath, sizeof(tmpPath), "%s/%s%s.tmp", dir_, name, SUFFIX);

    #ifdef _WIN32
        FILE* file = std::fopen(tmpPath, "wb");
        if (!file) return;
        const bool wrote = std::fwrite(bundle, 1, len, file) == len;
        std::fclose(file);
        if (!wrote) { std::remove(tmpPath); return; }
        MoveFileExA(tmpPath, finalPath, MOVEFILE_REPLACE_EXISTING);
    #else
        // Owner-only from birth: the descriptor is opened 0600, so there is
        // no window where the file exists wider than that.
        const int fd = ::open(tmpPath, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd < 0) return;
        size_t done = 0;
        while (done < len)
        {
            const ssize_t n = ::write(fd, bundle + done, len - done);
            if (n <= 0) { ::close(fd); ::unlink(tmpPath); return; }
            done += static_cast<size_t>(n);
        }
        ::close(fd);
        if (::rename(tmpPath, finalPath) != 0) ::unlink(tmpPath);
    #endif
    }

    void TicketFileStore::Remove(const uint8_t issuerId[32]) noexcept
    {
        if (!Active()) return;
        char name[HEX_ID + 1];
        HexId(issuerId, name);
        char path[MAX_DIR];
        std::snprintf(path, sizeof(path), "%s/%s%s", dir_, name, SUFFIX);
        std::remove(path);
    }

    void TicketFileStore::LoadAll(void* context,
                                  bool (*sink)(void*, const uint8_t*, size_t))
    {
        if (!Active() || !sink) return;

        uint8_t bundle[TicketTable::BUNDLE_MAX];

    #ifdef _WIN32
        char pattern[MAX_DIR];
        std::snprintf(pattern, sizeof(pattern), "%s/*%s", dir_, SUFFIX);
        WIN32_FIND_DATAA found;
        HANDLE walk = FindFirstFileA(pattern, &found);
        if (walk == INVALID_HANDLE_VALUE) return;
        do
        {
            char path[MAX_DIR];
            std::snprintf(path, sizeof(path), "%s/%s", dir_, found.cFileName);
            FILE* file = std::fopen(path, "rb");
            if (!file) continue;
            const size_t got = std::fread(bundle, 1, sizeof(bundle), file);
            std::fclose(file);
            if (got == 0 || !sink(context, bundle, got))
                std::remove(path);
        } while (FindNextFileA(walk, &found));
        FindClose(walk);
    #else
        DIR* walk = ::opendir(dir_);
        if (!walk) return;
        while (const dirent* item = ::readdir(walk))
        {
            const size_t nameLen = std::strlen(item->d_name);
            if (nameLen < sizeof(SUFFIX) - 1
                || std::strcmp(item->d_name + nameLen - (sizeof(SUFFIX) - 1), SUFFIX) != 0)
                continue;
            char path[MAX_DIR];
            std::snprintf(path, sizeof(path), "%s/%s", dir_, item->d_name);
            FILE* file = std::fopen(path, "rb");
            if (!file) continue;
            const size_t got = std::fread(bundle, 1, sizeof(bundle), file);
            std::fclose(file);
            if (got == 0 || !sink(context, bundle, got))
                std::remove(path);
        }
        ::closedir(walk);
    #endif
    }
}
