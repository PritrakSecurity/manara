#include "HeartbeatManager.h"
#include "HttpClient.h"
#include "../../common/utils/logging.h"
#include "../../common/utils/NetworkUtils.h"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <lmcons.h>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#else
#include <unistd.h>
#include <sys/utsname.h>
#endif

#include <sstream>
#include <chrono>
#include <iomanip>

// Simple JSON building (no external dependency)
static std::string EscapeJson(const std::string& s) {
    std::ostringstream o;
    for (char c : s) {
        switch (c) {
            case '"': o << "\\\""; break;
            case '\\': o << "\\\\"; break;
            case '\b': o << "\\b"; break;
            case '\f': o << "\\f"; break;
            case '\n': o << "\\n"; break;
            case '\r': o << "\\r"; break;
            case '\t': o << "\\t"; break;
            default:
                if ('\x00' <= c && c <= '\x1f') {
                    o << "\\u" << std::hex << std::setw(4) << std::setfill('0') << (int)c;
                } else {
                    o << c;
                }
        }
    }
    return o.str();
}

HeartbeatManager::HeartbeatManager()
    : isRunning_(false)
    , lastHeartbeatSuccess_(false)
    , consecutiveFailures_(0)
    , intervalSeconds_(30)
    , agentVersion_("1.0.0")
{
    httpClient_ = std::make_unique<HttpClient>();
}

HeartbeatManager::~HeartbeatManager() {
    Stop();
}

bool HeartbeatManager::Initialize(const std::string& backendUrl,
                                   const std::string& deviceId,
                                   const std::string& hostname) {
    backendUrl_ = backendUrl;
    deviceId_ = deviceId;
    hostname_ = hostname;

    // Set HTTP base URL
    httpClient_->SetBaseUrl(backendUrl);

    // Get system info
    std::string sysInfo = GetSystemInfo();

#ifdef _WIN32
    // Get local IP address
    char hostbuf[256];
    if (gethostname(hostbuf, sizeof(hostbuf)) == 0) {
        if (hostname_.empty()) {
            hostname_ = hostbuf;
        }
    }

    // Get OS version
    OSVERSIONINFOEXW osInfo = { sizeof(osInfo) };
    typedef LONG(WINAPI* RtlGetVersionPtr)(OSVERSIONINFOEXW*);
    RtlGetVersionPtr RtlGetVersion = (RtlGetVersionPtr)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion");
    if (RtlGetVersion && RtlGetVersion(&osInfo) == 0) {
        std::ostringstream oss;
        oss << "Windows " << osInfo.dwMajorVersion << "." << osInfo.dwMinorVersion 
            << " (Build " << osInfo.dwBuildNumber << ")";
        osVersion_ = oss.str();
    } else {
        osVersion_ = "Windows";
    }

    // Get the primary LAN IP address (prefers physical Ethernet/Wi-Fi NICs
    // over virtual adapters such as Docker/Hyper-V).
    ipAddress_ = NetworkUtils::GetPrimaryIPv4Address();
#else
    // Linux implementation
    char hostbuf[256];
    if (gethostname(hostbuf, sizeof(hostbuf)) == 0) {
        if (hostname_.empty()) {
            hostname_ = hostbuf;
        }
    }
    
    struct utsname buf;
    if (uname(&buf) == 0) {
        osVersion_ = std::string(buf.sysname) + " " + buf.release;
    }
    
    ipAddress_ = "127.0.0.1"; // Placeholder
#endif

    if (ipAddress_.empty()) {
        ipAddress_ = "127.0.0.1";
    }

    return true;
}

void HeartbeatManager::SetAuthToken(const std::string& token) {
    httpClient_->SetAuthToken(token);
}

void HeartbeatManager::SetCaCertificatePath(const std::string& caCertPath) {
    httpClient_->SetCaCertificatePath(caCertPath);
}

void HeartbeatManager::Start(int intervalSeconds) {
    if (isRunning_) {
        return;
    }

    intervalSeconds_ = intervalSeconds;
    isRunning_ = true;
    
    heartbeatThread_ = std::thread(&HeartbeatManager::HeartbeatLoop, this);
}

void HeartbeatManager::Stop() {
    isRunning_ = false;
    
    if (heartbeatThread_.joinable()) {
        heartbeatThread_.join();
    }
}

bool HeartbeatManager::SendHeartbeatNow() {
    std::string payload = BuildHeartbeatPayload();

    LOG_INFO("Sending heartbeat to %s", (backendUrl_ + "/api/devices/heartbeat").c_str());
    HttpClient::Response response = httpClient_->Post("/api/devices/heartbeat", payload);
    LOG_INFO("Heartbeat response: %d", response.statusCode);

    if (response.success) {
        lastHeartbeatSuccess_ = true;
        consecutiveFailures_ = 0;

        LOG_INFO("Heartbeat sent successfully (device=%s)", deviceId_.c_str());
        
        if (statusCallback_) {
            statusCallback_(true, 0);
        }
        return true;
    } else {
        lastHeartbeatSuccess_ = false;
        consecutiveFailures_++;

        LOG_WARNING("Heartbeat failed (device=%s): %s", deviceId_.c_str(), response.error.c_str());
        
        if (statusCallback_) {
            statusCallback_(false, consecutiveFailures_);
        }
        return false;
    }
}

void HeartbeatManager::SetStatusCallback(std::function<void(bool, int)> callback) {
    statusCallback_ = callback;
}

void HeartbeatManager::HeartbeatLoop() {
    // Send initial heartbeat immediately
    SendHeartbeatNow();
    
    while (isRunning_) {
        // Sleep in small increments to allow quick shutdown
        for (int i = 0; i < intervalSeconds_ && isRunning_; ++i) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        
        if (!isRunning_) break;
        
        SendHeartbeatNow();
    }
}

std::string HeartbeatManager::BuildHeartbeatPayload() {
    // Get current timestamp in ISO 8601 format
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::tm tm = *std::gmtime(&time);
    
    std::ostringstream timestamp;
    timestamp << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    
    // Build JSON payload manually (no external dependency)
    std::ostringstream json;
    json << "{"
         << "\"device_id\":\"" << EscapeJson(deviceId_) << "\","
         << "\"hostname\":\"" << EscapeJson(hostname_) << "\","
         << "\"ip_address\":\"" << EscapeJson(ipAddress_) << "\","
         << "\"agent_version\":\"" << EscapeJson(agentVersion_) << "\","
         << "\"os_version\":\"" << EscapeJson(osVersion_) << "\","
         << "\"status\":\"online\","
         << "\"timestamp\":\"" << timestamp.str() << "\""
         << "}";
    
    return json.str();
}

std::string HeartbeatManager::GetSystemInfo() {
    std::ostringstream info;
    
#ifdef _WIN32
    // Get computer name
    char compName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(compName);
    if (GetComputerNameA(compName, &size)) {
        info << "Computer: " << compName << "\n";
    }
    
    // Get username
    char userName[UNLEN + 1];
    size = sizeof(userName);
    if (GetUserNameA(userName, &size)) {
        info << "User: " << userName << "\n";
    }
#else
    char hostbuf[256];
    if (gethostname(hostbuf, sizeof(hostbuf)) == 0) {
        info << "Host: " << hostbuf << "\n";
    }
#endif
    
    return info.str();
}
