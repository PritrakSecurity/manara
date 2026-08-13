#pragma once

#include <string>
#include <thread>
#include <atomic>
#include <memory>
#include <queue>
#include <mutex>
#include <condition_variable>

// Forward declarations
class PolicyEngine;
class SecureComm;
class TelemetryCollector;
class NetworkMonitor;
class ClipboardMonitor;
class USBMonitor;

/**
 * Main DLP Agent class
 * Coordinates all agent components: policy engine, communication, monitoring
 */
class DLPAgent {
public:
    DLPAgent();
    ~DLPAgent();

    /**
     * Initialize the agent
     * @return true if initialization successful, false otherwise
     */
    bool Initialize();

    /**
     * Load policy from file or backend
     * @param policyPath Path to policy JSON file (optional, if empty fetches from backend)
     * @return true if policy loaded successfully, false otherwise
     */
    bool LoadPolicy(const std::string& policyPath = "");

    /**
     * Start monitoring operations
     * Launches background threads for file/USB/network/clipboard monitoring
     */
    void StartMonitoring();

    /**
     * Shutdown the agent gracefully
     * Stops all monitoring threads and cleans up resources
     */
    void Shutdown();

    /**
     * Check if agent is running
     * @return true if agent is active, false otherwise
     */
    bool IsRunning() const { return isRunning_; }

    /**
     * Get agent status information
     * @return JSON string with agent status
     */
    std::string GetStatus() const;

private:
    // Component initialization
    bool InitializeComponents();
    bool InitializeCommunication();
    bool InitializeMonitors();

    // Policy management
    bool LoadPolicyFromFile(const std::string& path);
    bool LoadPolicyFromBackend();
    void OnPolicyUpdate(const std::string& policyJson);

    // Event processing
    void ProcessEventLoop();
    void ProcessTelemetryQueue();
    void HandleKernelEvent(const std::string& eventJson);

    // Monitoring threads
    void FileMonitorThread();
    void NetworkMonitorThread();
    void ClipboardMonitorThread();
    void USBMonitorThread();
    void TelemetrySenderThread();

    // Component instances
    std::unique_ptr<PolicyEngine> policyEngine_;
    std::unique_ptr<SecureComm> commClient_;
    std::unique_ptr<TelemetryCollector> telemetryCollector_;
    std::unique_ptr<NetworkMonitor> networkMonitor_;
    std::unique_ptr<ClipboardMonitor> clipboardMonitor_;
    std::unique_ptr<USBMonitor> usbMonitor_;

    // Thread management
    std::atomic<bool> isRunning_;
    std::thread eventLoopThread_;
    std::thread telemetryThread_;
    std::thread fileMonitorThread_;
    std::thread networkMonitorThread_;
    std::thread clipboardMonitorThread_;
    std::thread usbMonitorThread_;

    // Telemetry queue
    std::queue<std::string> telemetryQueue_;
    std::mutex telemetryMutex_;
    std::condition_variable telemetryCondition_;

    // Configuration
    std::string backendUrl_;
    std::string agentId_;
    std::string policyPath_;
    bool failClosed_;  // If true, block all operations on policy load failure
};
