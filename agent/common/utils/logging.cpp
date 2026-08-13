#include "logging.h"
#include <cstdarg>
#include <cstdio>
#include <vector>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <time.h>

namespace dlp {
namespace utils {

// printf-style entry point backing the LOG_* macros.
void LogMessage(LogLevel level, const char* format, ...) {
    if (format == nullptr) {
        return;
    }

    va_list args;
    va_start(args, format);

    // Determine the required buffer size (excluding the NUL terminator).
    va_list argsCopy;
    va_copy(argsCopy, args);
    int length = _vscprintf(format, argsCopy);
    va_end(argsCopy);

    if (length < 0) {
        va_end(args);
        return;
    }

    std::vector<char> buffer(static_cast<size_t>(length) + 1);
    vsnprintf_s(buffer.data(), buffer.size(), _TRUNCATE, format, args);
    va_end(args);

    Logger::GetInstance().Log(level, std::string(buffer.data()));
}

Logger& Logger::GetInstance() {
    static Logger instance;
    return instance;
}

void Logger::Initialize(const std::wstring& logPath) {
    if (initialized) {
        return;
    }
    
    InitializeCriticalSection(&logLock);
    
    // Open log file
    logFileHandle = CreateFileW(
        logPath.c_str(),
        GENERIC_WRITE,
        FILE_SHARE_READ,
        NULL,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    
    if (logFileHandle != INVALID_HANDLE_VALUE) {
        SetFilePointer(logFileHandle, 0, NULL, FILE_END);
        initialized = true;
    }
}

void Logger::Shutdown() {
    if (!initialized) {
        return;
    }
    
    EnterCriticalSection(&logLock);
    
    if (logFileHandle != INVALID_HANDLE_VALUE) {
        CloseHandle(logFileHandle);
        logFileHandle = INVALID_HANDLE_VALUE;
    }
    
    LeaveCriticalSection(&logLock);
    DeleteCriticalSection(&logLock);
    
    initialized = false;
}

void Logger::Log(LogLevel level, const std::wstring& message) {
    if (!initialized) {
        return;
    }
    
    // Get current time
    SYSTEMTIME st;
    GetLocalTime(&st);
    
    // Format log entry
    std::wstringstream ss;
    ss << L"[" << std::setfill(L'0')
       << std::setw(4) << st.wYear << L"-"
       << std::setw(2) << st.wMonth << L"-"
       << std::setw(2) << st.wDay << L" "
       << std::setw(2) << st.wHour << L":"
       << std::setw(2) << st.wMinute << L":"
       << std::setw(2) << st.wSecond << L"] ";
    
    // Add level
    switch (level) {
        case LogLevel::DEBUG:
            ss << L"[DEBUG] ";
            break;
        case LogLevel::INFO:
            ss << L"[INFO] ";
            break;
        case LogLevel::WARNING:
            ss << L"[WARNING] ";
            break;
        case LogLevel::ERROR:
            ss << L"[ERROR] ";
            break;
        case LogLevel::CRITICAL:
            ss << L"[CRITICAL] ";
            break;
    }
    
    ss << message << L"\r\n";
    
    std::wstring logEntry = ss.str();
    
    // Write to file
    EnterCriticalSection(&logLock);
    
    if (logFileHandle != INVALID_HANDLE_VALUE) {
        DWORD bytesWritten;
        WriteFile(
            logFileHandle,
            logEntry.c_str(),
            static_cast<DWORD>(logEntry.length() * sizeof(wchar_t)),
            &bytesWritten,
            NULL
        );
        // Flush immediately so the log survives a crash and is visible to
        // readers (e.g. the backend's log download) in real time.
        FlushFileBuffers(logFileHandle);
    }
    
    LeaveCriticalSection(&logLock);
    
    // Also output to debugger if attached
    OutputDebugStringW(logEntry.c_str());
}

void Logger::Log(LogLevel level, const std::string& message) {
    // Convert to wide string
    int size = MultiByteToWideChar(CP_UTF8, 0, message.c_str(), -1, NULL, 0);
    std::wstring wmessage(size, 0);
    MultiByteToWideChar(CP_UTF8, 0, message.c_str(), -1, &wmessage[0], size);
    
    Log(level, wmessage);
}

void Logger::Debug(const std::wstring& message) {
    Log(LogLevel::DEBUG, message);
}

void Logger::Info(const std::wstring& message) {
    Log(LogLevel::INFO, message);
}

void Logger::Warning(const std::wstring& message) {
    Log(LogLevel::WARNING, message);
}

void Logger::Error(const std::wstring& message) {
    Log(LogLevel::ERROR, message);
}

void Logger::Critical(const std::wstring& message) {
    Log(LogLevel::CRITICAL, message);
}

} // namespace utils
} // namespace dlp
