#include "DLPAgent.h"
#include "../policy/PolicyEngine.h"
#include "../comms/SecureComm.h"
#include "../comms/HeartbeatManager.h"
#include "../comms/EventSender.h"
#include "../comms/KernelComm.h"
#include "../classification/ClassificationService.h"
#include "../quarantine/QuarantineManager.h"
#include "../telemetry/TelemetryCollector.h"
#include "../cache/LocalCache.h"
#include "../../common/utils/logging.h"
#include "../../common/config/Config.h"
#include "../../common/shared/dlp_shared.h"
#include <fstream>
#include <sstream>
#include <chrono>
#include <algorithm>
#include <windows.h>
#include <iphlpapi.h>
#include <lmcons.h>
#include <filesystem>

namespace {

std::wstring Utf8ToWide(const std::string& utf8) {
    if (utf8.empty()) {
        return L"";
    }
    int size = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), static_cast<int>(utf8.size()), nullptr, 0);
    std::wstring result(size, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), static_cast<int>(utf8.size()), &result[0], size);
    return result;
}

std::string WideToUtf8(const std::wstring& wide) {
    if (wide.empty()) {
        return "";
    }
    int size = WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), static_cast<int>(wide.size()), nullptr, 0, nullptr, nullptr);
    std::string result(size, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), static_cast<int>(wide.size()), &result[0], size, nullptr, nullptr);
    return result;
}

std::string GetOSVersionString() {
    OSVERSIONINFOEXW osInfo = { sizeof(osInfo) };
    typedef LONG(WINAPI* RtlGetVersionPtr)(OSVERSIONINFOEXW*);
    RtlGetVersionPtr RtlGetVersion = (RtlGetVersionPtr)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion");
    std::ostringstream oss;
    if (RtlGetVersion && RtlGetVersion(&osInfo) == 0) {
        oss << "Windows " << osInfo.dwMajorVersion << "." << osInfo.dwMinorVersion
            << " (Build " << osInfo.dwBuildNumber << ")";
    } else {
        oss << "Windows";
    }
    return oss.str();
}

std::string EventTypeToPolicyString(EventType type) {
    switch (type) {
        case EventType::FILE_WRITE: return "file_write";
        case EventType::USB_CONNECT:
        case EventType::USB_FILE_WRITE: return "usb_write";
        case EventType::NETWORK_FLOW: return "network_upload";
        case EventType::CLIPBOARD_READ:
        case EventType::CLIPBOARD_WRITE: return "clipboard";
        case EventType::FILE_ACCESS:
        default: return "file_access";
    }
}

} // namespace

DLPAgent::DLPAgent()
    : isRunning_(false)
{
    // Generate unique agent ID from machine GUID
    char hostname[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(hostname);
    if (GetComputerNameA(hostname, &size)) {
        agentId_ = std::string(hostname) + "-" + std::to_string(GetTickCount64());
    } else {
        agentId_ = "agent-" + std::to_string(std::chrono::system_clock::now().time_since_epoch().count());
    }
}

DLPAgent::~DLPAgent() {
    Shutdown();
}

bool DLPAgent::Initialize(const std::string& configPath) {
    configPath_ = configPath;

    LOG_INFO("Initializing DLP Agent (ID: %s)", agentId_.c_str());

    // Load configuration
    if (!configPath.empty()) {
        Config::GetInstance().Load(configPath);
        backendUrl_ = Config::GetInstance().GetBackendUrl();
        policyPath_ = Config::GetInstance().GetPolicyPath();
    } else {
        backendUrl_ = "grpcs://localhost:50051";
        policyPath_ = "C:\\ProgramData\\PritrakDLP\\policy.json";
    }

    // Validate configuration
    if (!ValidateConfiguration()) {
        LOG_ERROR("Configuration validation failed");
        return false;
    }

    // Initialize components
    policyEngine_ = std::make_unique<PolicyEngine>();
    secureComm_ = std::make_unique<SecureComm>();
    telemetryCollector_ = std::make_unique<TelemetryCollector>();
    localCache_ = std::make_unique<LocalCache>();
    heartbeatManager_ = std::make_unique<HeartbeatManager>();
    eventSender_ = std::make_unique<EventSender>();
    quarantineManager_ = std::make_unique<QuarantineManager>();

    // Initialize secure communication (strict TLS validation against ca.crt)
    if (!secureComm_->Initialize(backendUrl_, Config::GetInstance().GetCaCertPath())) {
        LOG_WARNING("Failed to initialize secure communication, will retry in background");
    }

    // Initialize local cache
    if (!localCache_->Initialize(Config::GetInstance().GetCachePath())) {
        LOG_WARNING("Failed to initialize local cache");
    }

    // Initialize the secure quarantine store (SYSTEM-only ACL).
    if (!quarantineManager_->Initialize(localCache_.get())) {
        LOG_ERROR("Failed to initialize quarantine manager; enforcement degrades to reporting only");
    }

    // Blocking is enforced at the kernel boundary; usermode sanitizes the
    // outcome (quarantine instead of deletion).
    telemetryCollector_->SetQuarantineManager(quarantineManager_.get());

    // Establish the bidirectional kernel driver channel (command + notify ports).
    InitializeKernelIntegration();

    // Initialize HTTP-based heartbeat manager (works without TLS)
    // Parse HTTP URL from gRPC URL if needed
    std::string httpBackendUrl = backendUrl_;
    if (httpBackendUrl.find("grpcs://") == 0 || httpBackendUrl.find("grpc://") == 0) {
        // Convert gRPC URL to HTTP URL (use port 8080 for HTTP API)
        size_t colonPos = httpBackendUrl.find("://");
        if (colonPos != std::string::npos) {
            std::string hostPart = httpBackendUrl.substr(colonPos + 3);
            size_t portPos = hostPart.find(':');
            std::string host = (portPos != std::string::npos) ? hostPart.substr(0, portPos) : hostPart;
            httpBackendUrl = "http://" + host + ":8080";
        }
    }

    // Get hostname
    char hostname[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD hostnameSize = sizeof(hostname);
    GetComputerNameA(hostname, &hostnameSize);

    // --- Auto-enrollment --------------------------------------------------
    // The agent must be fully enrolled: BOTH an agent_id and an auth token.
    // If either is missing, register the device with the backend
    // (POST /api/devices/register) and persist the issued id + token so they
    // survive reboots.
    std::string deviceId = agentId_;
    std::string authToken = Config::GetInstance().GetAuthToken();
    const std::string persistedAgentId = Config::GetInstance().GetAgentId();

    if (persistedAgentId.empty() || authToken.empty()) {
        LOG_INFO("Missing agent_id or auth token; registering device with backend");
        std::string enrolledToken;
        std::string enrolledDeviceId;
        if (SecureComm::RegisterDevice(httpBackendUrl, hostname, GetOSVersionString(), "1.0.0",
                                       enrolledToken, enrolledDeviceId)) {
            authToken = enrolledToken;
            deviceId = enrolledDeviceId;
            agentId_ = enrolledDeviceId;
            Config::GetInstance().SetAgentId(enrolledDeviceId);
            Config::GetInstance().SetAuthToken(enrolledToken);
            LOG_INFO("Auto-enrollment complete (device id=%s)", enrolledDeviceId.c_str());
        } else {
            LOG_WARNING("Auto-enrollment failed; heartbeats will attempt to register the device");
        }
    } else {
        // Fully enrolled: reuse the persisted identity across reboots.
        deviceId = persistedAgentId;
        agentId_ = persistedAgentId;
        LOG_INFO("Using existing enrollment token and agent id (%s)", persistedAgentId.c_str());
    }

    if (!heartbeatManager_->Initialize(httpBackendUrl, deviceId, hostname)) {
        LOG_WARNING("Failed to initialize heartbeat manager");
    }

    // Initialize event sender
    if (!eventSender_->Initialize(httpBackendUrl, deviceId)) {
        LOG_WARNING("Failed to initialize event sender");
    }

    // Strict TLS validation against the configured CA on every outbound client.
    const std::string caPath = Config::GetInstance().GetCaCertPath();
    if (!caPath.empty()) {
        heartbeatManager_->SetCaCertificatePath(caPath);
        eventSender_->SetCaCertificatePath(caPath);
    }

    // Inject the configured bearer token on every outbound request.
    // (authToken was resolved during auto-enrollment above.)
    if (!authToken.empty()) {
        secureComm_->SetAuthToken(authToken);
        heartbeatManager_->SetAuthToken(authToken);
        eventSender_->SetAuthToken(authToken);
        LOG_INFO("Authorization token injected on all outbound requests");
    } else {
        LOG_WARNING("No authToken configured; outbound requests will be unauthenticated");
    }

    // Load policy (from backend or local fallback)
    std::string policyJson;
    if (secureComm_->IsConnected()) {
        policyJson = secureComm_->FetchPolicy();
    }

    if (policyJson.empty() && !policyPath_.empty()) {
        // Try local fallback
        std::ifstream file(policyPath_);
        if (file.is_open()) {
            std::stringstream buffer;
            buffer << file.rdbuf();
            policyJson = buffer.str();
        }
    }

    if (!policyJson.empty()) {
        if (!policyEngine_->LoadRules(policyJson)) {
            LOG_ERROR("Failed to load policy");
            return false;
        }
        // Cache policy locally
        localCache_->StorePolicy(policyJson);
    } else {
        LOG_WARNING("No policy available, using default deny");
    }

    LOG_INFO("DLP Agent initialized successfully");
    return true;
}

bool DLPAgent::Start() {
    if (isRunning_) {
        LOG_WARNING("Agent is already running");
        return false;
    }

    isRunning_ = true;

    // Start event loop
    eventLoopThread_ = std::thread(&DLPAgent::EventLoop, this);

    // Start policy refresh thread
    policyRefreshThread_ = std::thread(&DLPAgent::RefreshPolicy, this);

    // Start telemetry sender
    telemetrySenderThread_ = std::thread(&DLPAgent::SendTelemetry, this);

    // Start HTTP-based heartbeat manager (30 second interval)
    if (heartbeatManager_) {
        heartbeatManager_->Start(30);
        LOG_INFO("HTTP Heartbeat manager started (30s interval)");
    }

    // Start legacy heartbeat sender for gRPC (every 30s by default)
    heartbeatThread_ = std::thread(&DLPAgent::SendHeartbeatLoop, this);

    // Start event sender
    if (eventSender_) {
        eventSender_->Start(50, 5000);  // Batch size 50, 5 second timeout
        LOG_INFO("Event sender started");
    }

    // Start telemetry collection
    telemetryCollector_->Start();

    // Start the kernel driver monitor (reconnect with exponential backoff).
    driverMonitorThread_ = std::thread(&DLPAgent::DriverMonitorLoop, this);

    // Kick off a background classification scan of common user directories.
    StartClassificationScan();

    LOG_INFO("DLP Agent started");
    return true;
}

void DLPAgent::Stop() {
    if (!isRunning_) {
        return;
    }

    LOG_INFO("Stopping DLP Agent...");
    isRunning_ = false;

    // Signal threads to stop
    eventQueueCondition_.notify_all();

    // Stop telemetry collection
    if (telemetryCollector_) {
        telemetryCollector_->Stop();
    }

    // Stop HTTP heartbeat manager
    if (heartbeatManager_) {
        heartbeatManager_->Stop();
    }

    // Stop event sender
    if (eventSender_) {
        eventSender_->Stop();
    }

    // Wait for threads
    if (driverMonitorThread_.joinable()) driverMonitorThread_.join();
    if (classificationScanThread_.joinable()) classificationScanThread_.join();
    if (eventLoopThread_.joinable()) eventLoopThread_.join();
    if (policyRefreshThread_.joinable()) policyRefreshThread_.join();
    if (telemetrySenderThread_.joinable()) telemetrySenderThread_.join();
    if (heartbeatThread_.joinable()) heartbeatThread_.join();

    LOG_INFO("DLP Agent stopped");
}

void DLPAgent::Shutdown() {
    Stop();

    // Stop kernel driver communication (releases notify/command ports)
    Pritrak::DLP::KernelComm::GetInstance().Shutdown();

    // Flush cache
    if (localCache_) {
        localCache_->Shutdown();
    }

    // Release quarantine access locks and close the workspace handles
    if (quarantineManager_) {
        quarantineManager_->Shutdown();
    }

    // Disconnect from backend
    if (secureComm_) {
        secureComm_->Disconnect();
    }
}

bool DLPAgent::InstallService() {
    SC_HANDLE scManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!scManager) {
        LOG_ERROR("Failed to open service control manager");
        return false;
    }

    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);

    SC_HANDLE service = CreateServiceA(
        scManager,
        "PritrakDLP",
        "Pritrak DLP Agent",
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START,
        SERVICE_ERROR_NORMAL,
        exePath,
        NULL, NULL, NULL, NULL, NULL
    );

    CloseServiceHandle(scManager);

    if (!service) {
        DWORD error = GetLastError();
        if (error == ERROR_SERVICE_EXISTS) {
            LOG_INFO("Service already exists");
            return true;
        }
        LOG_ERROR("Failed to create service: %lu", error);
        return false;
    }

    CloseServiceHandle(service);
    LOG_INFO("Service installed successfully");
    return true;
}

bool DLPAgent::UninstallService() {
    SC_HANDLE scManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scManager) {
        LOG_ERROR("Failed to open service control manager");
        return false;
    }

    SC_HANDLE service = OpenServiceA(scManager, "PritrakDLP", SERVICE_STOP | DELETE);
    if (!service) {
        CloseServiceHandle(scManager);
        LOG_ERROR("Failed to open service");
        return false;
    }

    // Stop service first
    SERVICE_STATUS status;
    ControlService(service, SERVICE_CONTROL_STOP, &status);

    // Delete service
    bool result = DeleteService(service) != 0;
    CloseServiceHandle(service);
    CloseServiceHandle(scManager);

    if (result) {
        LOG_INFO("Service uninstalled successfully");
    } else {
        LOG_ERROR("Failed to uninstall service");
    }

    return result;
}

bool DLPAgent::IsServiceInstalled() {
    SC_HANDLE scManager = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scManager) {
        return false;
    }

    SC_HANDLE service = OpenServiceA(scManager, "PritrakDLP", SERVICE_QUERY_STATUS);
    CloseServiceHandle(scManager);

    if (!service) {
        return false;
    }

    CloseServiceHandle(service);
    return true;
}

void DLPAgent::EventLoop() {
    while (isRunning_) {
        std::unique_lock<std::mutex> lock(eventQueueMutex_);
        eventQueueCondition_.wait(lock, [this] { return !eventQueue_.empty() || !isRunning_; });

        if (!isRunning_) break;

        if (!eventQueue_.empty()) {
            Event event = eventQueue_.front();
            eventQueue_.pop();
            lock.unlock();

            ProcessEvent(event);
        }
    }
}

void DLPAgent::ProcessEvent(const Event& event) {
    // Convert the agent event into the policy engine's representation.
    PolicyEvent policyEvent;
    policyEvent.eventType = EventTypeToPolicyString(event.type);
    policyEvent.operation = "MONITOR";
    policyEvent.sourcePath = event.filePath;
    policyEvent.destinationPath = event.deviceName;
    policyEvent.application = event.processName;
    policyEvent.userId = event.userId;
    policyEvent.dataContent = event.data;

    // Evaluate policy
    PolicyAction action = policyEngine_->EvaluateEvent(policyEvent);

    // Execute action
    switch (action) {
        case PolicyAction::ALLOW:
            // Allow operation
            break;
        case PolicyAction::BLOCK:
            // Block operation. The kernel boundary prevents the I/O; here we
            // sanitize the outcome by securely quarantining the offending file.
            // NEVER delete user data.
            LOG_WARNING("Blocking event: %s", event.filePath.c_str());
            if (quarantineManager_ && !event.filePath.empty()) {
                if (Config::GetInstance().GetEnforcementMode() == "MONITOR_ONLY") {
                    LOG_INFO("MONITOR_ONLY: Would have quarantined file %s but skipping.", event.filePath.c_str());
                } else if (!quarantineManager_->QuarantineFile(
                        Utf8ToWide(event.filePath),
                        L"BLOCKED",
                        Utf8ToWide(event.userId),
                        L"Policy violation")) {
                    LOG_WARNING("Failed to quarantine blocked file %s; file left in place", event.filePath.c_str());
                }
            }
            break;
        case PolicyAction::LOG:
        case PolicyAction::QUARANTINE:
        case PolicyAction::ENCRYPT:
        case PolicyAction::REDACT:
        default:
            // Log and allow
            LOG_INFO("Logging event: %s", event.filePath.c_str());
            break;
    }

    // Queue for telemetry
    if (telemetryCollector_) {
        telemetryCollector_->CollectEvent(event);
    }
}

void DLPAgent::EnqueueEvent(const Event& event) {
    std::lock_guard<std::mutex> lock(eventQueueMutex_);
    eventQueue_.push(event);
    eventQueueCondition_.notify_one();
}

void DLPAgent::RefreshPolicy() {
    while (isRunning_) {
        std::this_thread::sleep_for(std::chrono::seconds(300)); // Every 5 minutes

        if (secureComm_ && secureComm_->IsConnected()) {
            std::string policyJson = secureComm_->FetchPolicy();
            if (!policyJson.empty()) {
                if (policyEngine_->LoadRules(policyJson)) {
                    LOG_INFO("Policy refreshed from backend");
                    localCache_->StorePolicy(policyJson);
                }
            }
        }
    }
}

void DLPAgent::SendTelemetry() {
    while (isRunning_) {
        std::this_thread::sleep_for(std::chrono::seconds(10)); // Every 10 seconds

        if (telemetryCollector_) {
            std::vector<Event> events = telemetryCollector_->GetBatch(100);

            if (!events.empty()) {
                if (secureComm_ && secureComm_->IsConnected()) {
                    if (secureComm_->SendEvents(events)) {
                        LOG_DEBUG("Sent %zu events to backend", events.size());
                    } else {
                        // Cache events for later
                        for (const auto& event : events) {
                            localCache_->StoreEvent(event);
                        }
                    }
                } else {
                    // Cache events for later
                    for (const auto& event : events) {
                        localCache_->StoreEvent(event);
                    }
                }
            }
        }

        // Try to flush cached events
        if (secureComm_ && secureComm_->IsConnected() && localCache_) {
            localCache_->SyncEvents(secureComm_.get());
        }
    }
}

void DLPAgent::SendHeartbeatLoop() {
    while (isRunning_) {
        std::this_thread::sleep_for(std::chrono::seconds(Config::GetInstance().GetHeartbeatIntervalSeconds()));

        if (!isRunning_) break;

        // Send heartbeat via secure comm if available
        if (secureComm_ && secureComm_->IsConnected()) {
            if (!secureComm_->SendHeartbeat()) {
                LOG_WARNING("Heartbeat failed to send to backend");
            } else {
                LOG_DEBUG("Heartbeat sent successfully");
            }
        } else {
            // Try to establish connection if not connected
            if (secureComm_ && !secureComm_->IsConnected()) {
                secureComm_->Connect();
            }
        }
    }
}

namespace {
std::wstring ClassificationToString(ULONG classification) {
    if (classification & DLP_CLASS_TOP_SECRET) return L"TOP_SECRET";
    if (classification & DLP_CLASS_RESTRICTED) return L"RESTRICTED";
    if (classification & DLP_CLASS_CONFIDENTIAL) return L"CONFIDENTIAL";
    if (classification & DLP_CLASS_PII) return L"PII";
    return L"UNKNOWN";
}
} // namespace

void DLPAgent::InitializeKernelIntegration() {
    using namespace Pritrak::DLP;

    auto& kernelComm = KernelComm::GetInstance();

    kernelComm.RegisterBlockEventCallback([this](const DLP_EVENT_NOTIFICATION& event) {
        OnKernelBlockEvent(event);
    });

    kernelComm.RegisterConnectionCallback([](bool connected) {
        LOG_INFO("Kernel driver connection: %s", connected ? "connected" : "disconnected");
    });

    if (!kernelComm.Initialize()) {
        LOG_WARNING("Kernel driver not available; reconnect will be attempted in background");
    } else {
        // Enforce (not audit) and fail open (allow + audit) when no policy is cached.
        kernelComm.UpdateConfig(false, false, 65536, 300);
    }
}

void DLPAgent::DriverMonitorLoop() {
    using namespace Pritrak::DLP;

    int attempt = 0;
    const int maxAttempts = 10;

    while (isRunning_) {
        auto& kernelComm = KernelComm::GetInstance();

        if (!kernelComm.IsConnected()) {
            // Exponential backoff: 1s, 2s, 4s, 8s, 16s (capped). Uses an
            // explicit wait (sleep) rather than a busy spin.
            int delayMs = 1000 << std::min(attempt, 4);
            std::this_thread::sleep_for(std::chrono::milliseconds(delayMs));

            if (!isRunning_) {
                break;
            }

            if (kernelComm.Initialize()) {
                attempt = 0;
                kernelComm.UpdateConfig(false, false, 65536, 300);
                LOG_INFO("Kernel driver connection established");
            } else if (attempt < maxAttempts) {
                attempt++;
            }
        } else {
            // Connected: wait quietly between health checks.
            std::this_thread::sleep_for(std::chrono::seconds(30));
        }
    }
}

void DLPAgent::OnKernelBlockEvent(const DLP_EVENT_NOTIFICATION& event) {
    LOG_INFO("Kernel block event: operation=%u file=%ws",
        event.Operation, event.FilePath);

    // Quarantine exfiltration targets (atomically moved, NEVER deleted).
    // In MONITOR_ONLY mode the agent never quarantines anything.
    if (quarantineManager_ && event.FilePath[0] != L'\0') {
        if (Config::GetInstance().GetEnforcementMode() == "MONITOR_ONLY") {
            LOG_INFO("MONITOR_ONLY: Would have quarantined file %ws but skipping.", event.FilePath);
        } else {
            quarantineManager_->QuarantineFile(
                event.FilePath,
                ClassificationToString(event.Classification),
                L"",
                L"kernel enforcement");
        }
    }

    // Feed a synthetic event through the normal telemetry path.
    Event ev;
    ev.type = EventType::FILE_ACCESS;
    ev.agentId = agentId_;
    ev.filePath = WideToUtf8(event.FilePath);
    ev.processName = WideToUtf8(event.ProcessName);
    ev.timestamp = std::chrono::system_clock::now();
    ev.severity = Severity::HIGH;
    ev.data = "kernel-blocked operation=" + std::to_string(event.Operation);

    EnqueueEvent(ev);
}

void DLPAgent::StartClassificationScan() {
    using namespace Pritrak::DLP;

    if (classificationScanThread_.joinable()) {
        return;
    }

    classificationScanThread_ = std::thread([this]() {
        if (!isRunning_) {
            return;
        }

        auto& classificationService = ClassificationService::GetInstance();
        if (!classificationService.Initialize()) {
            LOG_WARNING("Classification service failed to initialize");
            return;
        }

        classificationService.LoadRulesFromJson("");

        wchar_t userProfile[MAX_PATH];
        if (GetEnvironmentVariableW(L"USERPROFILE", userProfile, MAX_PATH)) {
            std::wstring desktop = std::wstring(userProfile) + L"\\Desktop";
            std::wstring documents = std::wstring(userProfile) + L"\\Documents";
            std::wstring downloads = std::wstring(userProfile) + L"\\Downloads";

            classificationService.ScanDirectory(desktop, true);
            classificationService.ScanDirectory(documents, true);
            classificationService.ScanDirectory(downloads, true);
        }

        LOG_INFO("Classification scan complete: %zu protected files",
            classificationService.GetProtectedFileCount());
    });
}

bool DLPAgent::ValidateConfiguration() {
    if (backendUrl_.empty()) {
        LOG_ERROR("Backend URL not configured");
        return false;
    }
    return true;
}
