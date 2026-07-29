#pragma once

#include <cstdint>

namespace bcp::common {

    enum class LogLevel : uint8_t {
        Trace       = 0,
        Debug       = 1,
        Info        = 2,
        Warning     = 3,
        Error       = 4,
        Critical    = 5,
        None        = 255,
    };
    
    void Log(LogLevel level, const char* message);
    void LogF(LogLevel level, const char* fmt, ...);

    using LogCallback = void(*)(LogLevel level, const char* message);

    void DefaultLogCallback(LogLevel level, const char* message);
}