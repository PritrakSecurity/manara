#include "Agent.h"
#include "../policy/PolicyEngine.h"
#include "../comms/SecureComm.h"
#include "../telemetry/telemetry_collector.h"
#include "../network/network_monitor.h"
#include "../common/utils/logging.h"
#include <fstream>
#include <sstream>
#include <chrono>
#include <future>

// Forward declarations for monitors (to be implemented)
class ClipboardMonitor {
public:
    bool Start() { return true; }
    void Stop() {}
};

class USBMonitor {
public:
    bool Start() { return true; }
    void Stop() {}
};

DLPAgent::DLPAgent()
    : isRunning_(false)
    , failClosed_(true)  // Default to fail-closed
{
    // Generate unique agent ID (use machine GUID or generate UUID)
    agentId_ = "agent-" + std::to_string(std::chrono::system_clock::now().time_since_epoch().count());
    backendUrl_ = "https://localhost:50051";  // Default, should be from config
}

DLPAgent::~DLPAgent() {
    Shutdown();
}

bool DLPAgent::Initialize() {
    LOG_INFO("Initializing DLP Agent...");

    // Initialize components
    if (!InitializeComponents()) {
        LOG_ERROR("Failed to initialize agent components");
        return false;
    }

    // Initialize communication
    if (!InitializeCommunication()) {
        LOG_ERROR("Failed to initialize communication client");
        return false;
    }

    // Initialize monitors
    if (!InitializeMonitors()) {
        LOG_ERROR("Failed to initialize monitors");
        return false;
    }

    LOG_INFO("DLP Agent initialized successfully");
    return true;
}

bool DLPAgent::InitializeComponents() {
    try {
        // Initialize policy engine
        policyEngine_ = std::make_unique<PolicyEngine>();
        if (!policyEngine_) {
            LOG_ERROR("Failed to create policy engine");
            return false;
        }

        // Initialize telemetry collector
        telemetryCollector_ = std::make_unique<TelemetryCollector>();
        if (!telemetryCollector_) {
            LOG_ERROR("Failed to create telemetry collector");
            return false;
        }

        return true;
    } catch (const std::exception& e) {
        LOG_ERROR("Exception in InitializeComponents: %s", e.what());
        return false;
    }
}

bool DLPAgent::InitializeCommunication() {
    try {
        commClient_ = std::make_unique<SecureComm>();
        if (!commClient_) {
            LOG_ERROR("Failed to create secure communication client");
            return false;
        }

        // Connect to backend (non-blocking, will retry in background)
        std::future<bool> connectFuture = std::async(std::launch::async, [this]() {
            return commClient_->Connect(backendUrl_);
        });

        // Don't block on initial connection - allow offline operation
        // Connection will be retried in background
        return true;
    } catch (const std::exception& e) {
        LOG_ERROR("Exception in InitializeCommunication: %s", e.what());
        return false;
    }
}

bool DLPAgent::InitializeMonitors() {
    try {
        // Initialize network monitor
        networkMonitor_ = std::make_unique<NetworkMonitor>();
        if (!networkMonitor_) {
            LOG_ERROR("Failed to create network monitor");
            return false;
        }

        // Initialize clipboard monitor
        clipboardMonitor_ = std::make_unique<ClipboardMonitor>();
        if (!clipboardMonitor_) {
            LOG_ERROR("Failed to create clipboard monitor");
            return false;
        }

        // Initialize USB monitor
        usbMonitor_ = std::make_unique<USBMonitor>();
        if (!usbMonitor_) {
            LOG_ERROR("Failed to create USB monitor");
            return false;
        }

        return true;
    } catch (const std::exception& e) {
        LOG_ERROR("Exception in InitializeMonitors: %s", e.what());
        return false;
    }
}

bool DLPAgent::LoadPolicy(const std::string& policyPath) {
    policyPath_ = policyPath;

    bool success = false;
    if (!policyPath.empty()) {
        // Load from file
        success = LoadPolicyFromFile(policyPath);
    } else {
        // Try to load from backend
        success = LoadPolicyFromBackend();
        if (!success) {
            // If backend unavailable and fail-closed, block all operations
            if (failClosed_) {
                LOG_CRITICAL("Policy load failed and fail-closed enabled - blocking all operations");
                // Policy engine should default to deny
                return false;
            }
        }
    }

    if (success) {
        LOG_INFO("Policy loaded successfully");
    } else {
        LOG_ERROR("Failed to load policy");
    }

    return success;
}

bool DLPAgent::LoadPolicyFromFile(const std::string& path) {
    try {
        std::ifstream file(path);
        if (!file.is_open()) {
            LOG_ERROR("Failed to open policy file: %s", path.c_str());
            return false;
        }

        std::stringstream buffer;
        buffer << file.rdbuf();
        std::string policyJson = buffer.str();

        if (policyEngine_->LoadRules(policyJson)) {
            LOG_INFO("Policy loaded from file: %s", path.c_str());
            return true;
        } else {
            LOG_ERROR("Failed to parse policy JSON");
            return false;
        }
    } catch (const std::exception& e) {
        LOG_ERROR("Exception loading policy from file: %s", e.what());
        return false;
    }
}

bool DLPAgent::LoadPolicyFromBackend() {
    if (!commClient_ || !commClient_->IsConnected()) {
        LOG_WARNING("Backend not connected, cannot load policy");
        return false;
    }

    try {
        std::string policyJson = commClient_->FetchPolicy();
        if (policyJson.empty()) {
            LOG_ERROR("Received empty policy from backend");
            return false;
        }

        if (policyEngine_->LoadRules(policyJson)) {
            LOG_INFO("Policy loaded from backend");
            return true;
        } else {
            LOG_ERROR("Failed to parse policy from backend");
            return false;
        }
    } catch (const std::exception& e) {
        LOG_ERROR("Exception loading policy from backend: %s", e.what());
        return false;
    }
}

void DLPAgent::OnPolicyUpdate(const std::string& policyJson) {
    if (policyEngine_->LoadRules(policyJson)) {
        LOG_INFO("Policy updated successfully");
    } else {
        LOG_ERROR("Failed to update policy");
    }
}

void DLPAgent::StartMonitoring() {
    if (isRunning_) {
        LOG_WARNING("Agent is already running");
        return;
    }

    isRunning_ = true;

    // Start event processing loop
    eventLoopThread_ = std::thread(&DLPAgent::ProcessEventLoop, this);

    // Start telemetry sender
    telemetryThread_ = std::thread(&DLPAgent::TelemetrySenderThread, this);

    // Start monitoring threads
    fileMonitorThread_ = std::thread(&DLPAgent::FileMonitorThread, this);
    networkMonitorThread_ = std::thread(&DLPAgent::NetworkMonitorThread, this);
    clipboardMonitorThread_ = std::thread(&DLPAgent::ClipboardMonitorThread, this);
    usbMonitorThread_ = std::thread(&DLPAgent::USBMonitorThread, this);

    LOG_INFO("Monitoring started");
}

void DLPAgent::Shutdown() {
    if (!isRunning_) {
        return;
    }

    LOG_INFO("Shutting down DLP Agent...");

    isRunning_ = false;

    // Signal threads to stop
    telemetryCondition_.notify_all();

    // Stop monitors
    if (networkMonitor_) networkMonitor_->Stop();
    if (clipboardMonitor_) clipboardMonitor_->Stop();
    if (usbMonitor_) usbMonitor_->Stop();

    // Wait for threads to finish
    if (eventLoopThread_.joinable()) eventLoopThread_.join();
    if (telemetryThread_.joinable()) telemetryThread_.join();
    if (fileMonitorThread_.joinable()) fileMonitorThread_.join();
    if (networkMonitorThread_.joinable()) networkMonitorThread_.join();
    if (clipboardMonitorThread_.joinable()) clipboardMonitorThread_.join();
    if (usbMonitorThread_.joinable()) usbMonitorThread_.join();

    // Disconnect from backend
    if (commClient_) {
        commClient_->Disconnect();
    }

    LOG_INFO("DLP Agent shut down complete");
}

void DLPAgent::ProcessEventLoop() {
    while (isRunning_) {
        // Process kernel events, file system events, etc.
        // This would typically receive events from minifilter driver
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

void DLPAgent::ProcessTelemetryQueue() {
    std::lock_guard<std::mutex> lock(telemetryMutex_);
    while (!telemetryQueue_.empty()) {
        std::string event = telemetryQueue_.front();
        telemetryQueue_.pop();

        if (telemetryCollector_) {
            telemetryCollector_->CollectEvent(event);
        }
    }
}

void DLPAgent::HandleKernelEvent(const std::string& eventJson) {
    // Parse event and evaluate policy
    if (policyEngine_) {
        // PolicyEngine::EvaluateEvent would return Action (ALLOW/BLOCK/LOG)
        // For now, just queue for telemetry
        std::lock_guard<std::mutex> lock(telemetryMutex_);
        telemetryQueue_.push(eventJson);
        telemetryCondition_.notify_one();
    }
}

void DLPAgent::FileMonitorThread() {
    while (isRunning_) {
        // Monitor file system operations
        // This would integrate with minifilter driver
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }
}

void DLPAgent::NetworkMonitorThread() {
    if (networkMonitor_) {
        networkMonitor_->Start();
    }

    while (isRunning_) {
        // Network monitoring handled by WFP callout driver
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }

    if (networkMonitor_) {
        networkMonitor_->Stop();
    }
}

void DLPAgent::ClipboardMonitorThread() {
    if (clipboardMonitor_) {
        clipboardMonitor_->Start();
    }

    while (isRunning_) {
        // Clipboard monitoring
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    if (clipboardMonitor_) {
        clipboardMonitor_->Stop();
    }
}

void DLPAgent::USBMonitorThread() {
    if (usbMonitor_) {
        usbMonitor_->Start();
    }

    while (isRunning_) {
        // USB device monitoring
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }

    if (usbMonitor_) {
        usbMonitor_->Stop();
    }
}

void DLPAgent::TelemetrySenderThread() {
    while (isRunning_) {
        std::unique_lock<std::mutex> lock(telemetryMutex_);
        telemetryCondition_.wait(lock, [this] { return !telemetryQueue_.empty() || !isRunning_; });

        if (!isRunning_) break;

        // Process telemetry queue
        ProcessTelemetryQueue();

        // Send telemetry to backend (non-blocking)
        if (commClient_ && commClient_->IsConnected() && telemetryCollector_) {
            std::vector<std::string> events = telemetryCollector_->GetPendingEvents();
            if (!events.empty()) {
                commClient_->SendTelemetry(events);
                telemetryCollector_->ClearEvents();
            }
        }

        lock.unlock();
        std::this_thread::sleep_for(std::chrono::seconds(5));  // Send every 5 seconds
    }
}

std::string DLPAgent::GetStatus() const {
    std::stringstream ss;
    ss << "{"
       << "\"agent_id\":\"" << agentId_ << "\","
       << "\"running\":" << (isRunning_ ? "true" : "false") << ","
       << "\"policy_loaded\":" << (policyEngine_ ? "true" : "false") << ","
       << "\"backend_connected\":" << (commClient_ && commClient_->IsConnected() ? "true" : "false")
       << "}";
    return ss.str();
}
