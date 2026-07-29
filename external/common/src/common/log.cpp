#include <common/log.h>

#include <atomic>
#include <mutex>
#include <chrono>
#include <cstdio>
#include <cstdarg>
#include <ctime>

namespace bcp::common {

    namespace {
        std::atomic<uint64_t> sequence_{0};
        std::mutex writeMutex_;

        const char* LevelToString(LogLevel level) {
            switch (level) {
                case LogLevel::Trace:    return "TRACE";
                case LogLevel::Debug:    return "DEBUG";
                case LogLevel::Info:     return "INFO ";
                case LogLevel::Warning:  return "WARN ";
                case LogLevel::Error:    return "ERROR";
                case LogLevel::Critical: return "CRIT ";
                default:                 return "?????";
            }
        }
    }

    void Log(LogLevel level, const char* message) {
        DefaultLogCallback(level, message);
    }

    void LogF(LogLevel level, const char* fmt, ...) {
        char buffer[512];
        va_list args;
        va_start(args, fmt);
        std::vsnprintf(buffer, sizeof(buffer), fmt, args);
        va_end(args);

        DefaultLogCallback(level, buffer);
    }

    void DefaultLogCallback(LogLevel level, const char* message) {
        uint64_t seq = sequence_.fetch_add(1, std::memory_order_relaxed);

        std::lock_guard lock(writeMutex_);

        auto now = std::chrono::system_clock::now();
        auto t = std::chrono::system_clock::to_time_t(now);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            now.time_since_epoch()
        ).count() % 1000;

        std::tm tm;
        #ifdef _WIN32
            localtime_s(&tm, &t);
        #else
            localtime_r(&t, &tm);
        #endif

        std::printf("[%02d:%02d:%02d.%03lld] [#%llu] [%s] %s\n",
            tm.tm_hour, tm.tm_min, tm.tm_sec, static_cast<long long>(ms),
            static_cast<unsigned long long>(seq),
            LevelToString(level),
            message
        );
        std::fflush(stdout);
    }
}