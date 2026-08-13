#pragma once

#include <windows.h>
#include <string>

// windows.h (winerror.h) defines ERROR=0 which collides with the LogLevel
// enumerator below.
#ifdef ERROR
#undef ERROR
#endif

namespace dlp {
namespace utils {

enum class LogLevel {
    DEBUG = 0,
    INFO = 1,
    WARNING = 2,
    ERROR = 3,
    CRITICAL = 4
};

// printf-style logger entry point used by the LOG_* convenience macros.
void LogMessage(LogLevel level, const char* format, ...);

class Logger {
public:
    static Logger& GetInstance();
    
    void Initialize(const std::wstring& logPath);
    void Shutdown();
    
    void Log(LogLevel level, const std::wstring& message);
    void Log(LogLevel level, const std::string& message);
    
    void Debug(const std::wstring& message);
    void Info(const std::wstring& message);
    void Warning(const std::wstring& message);
    void Error(const std::wstring& message);
    void Critical(const std::wstring& message);

private:
    Logger() = default;
    ~Logger() = default;
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;
    
    HANDLE logFileHandle;
    CRITICAL_SECTION logLock;
    bool initialized;
};

// printf-style convenience macros (used throughout the agent)
#define LOG_DEBUG(...)     ::dlp::utils::LogMessage(::dlp::utils::LogLevel::DEBUG, __VA_ARGS__)
#define LOG_INFO(...)      ::dlp::utils::LogMessage(::dlp::utils::LogLevel::INFO, __VA_ARGS__)
#define LOG_WARNING(...)   ::dlp::utils::LogMessage(::dlp::utils::LogLevel::WARNING, __VA_ARGS__)
#define LOG_ERROR(...)     ::dlp::utils::LogMessage(::dlp::utils::LogLevel::ERROR, __VA_ARGS__)
#define LOG_CRITICAL(...)  ::dlp::utils::LogMessage(::dlp::utils::LogLevel::CRITICAL, __VA_ARGS__)

// Legacy one-argument macros
#define DLP_LOG_DEBUG(msg) dlp::utils::Logger::GetInstance().Debug(msg)
#define DLP_LOG_INFO(msg) dlp::utils::Logger::GetInstance().Info(msg)
#define DLP_LOG_WARNING(msg) dlp::utils::Logger::GetInstance().Warning(msg)
#define DLP_LOG_ERROR(msg) dlp::utils::Logger::GetInstance().Error(msg)
#define DLP_LOG_CRITICAL(msg) dlp::utils::Logger::GetInstance().Critical(msg)

} // namespace utils
} // namespace dlp
