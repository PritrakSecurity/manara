#pragma once

#include <string>
#include <memory>
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>
#include <queue>
#include <condition_variable>
#include "EventTypes.h"

// Forward declarations
class PolicyEngine;
class SecureComm;
class TelemetryCollector;
class LocalCache;
class HeartbeatManager;
class EventSender;
class QuarantineManager;

namespace Pritrak {
namespace DLP {
class KernelComm;
class ClassificationService;
} // namespace DLP
} // namespace Pritrak

/**
 * Main DLP Agent orchestrator
 * Coordinates policy engine, secure communication, telemetry collection, and local caching
 */
class DLPAgent {
public:
    DLPAgent();
    ~DLPAgent();

    /**
     * Initialize the agent with configuration
     * @param configPath Path to configuration file
     * @return true if initialization successful, false otherwise
     */
    bool Initialize(const std::string& configPath);

    /**
     * Start the agent (launches monitoring threads)
     * @return true if started successfully, false otherwise
     */
    bool Start();

    /**
     * Stop the agent gracefully
     */
    void Stop();

    /**
     * Whether the agent's main loops are still running
     */
    bool IsRunning() const { return isRunning_.load(); }

    /**
     * Shutdown and cleanup resources
     */
    void Shutdown();

    /**
     * Install as Windows Service
     * @return true if installation successful, false otherwise
     */
    static bool InstallService();

    /**
     * Uninstall Windows Service
     * @return true if uninstallation successful, false otherwise
     */
    static bool UninstallService();

    /**
     * Check if service is installed
     * @return true if installed, false otherwise
     */
    static bool IsServiceInstalled();
    
     // Enqueue an event into the agent's processing queue
     void EnqueueEvent(const Event& event);

private:
    // Component instances
    std::unique_ptr<PolicyEngine> policyEngine_;
    std::unique_ptr<SecureComm> secureComm_;
    std::unique_ptr<TelemetryCollector> telemetryCollector_;
    std::unique_ptr<LocalCache> localCache_;
    std::unique_ptr<HeartbeatManager> heartbeatManager_;
    std::unique_ptr<EventSender> eventSender_;
    std::unique_ptr<QuarantineManager> quarantineManager_;

    // Thread management
    std::atomic<bool> isRunning_;
    std::thread eventLoopThread_;
    std::thread policyRefreshThread_;
    std::thread telemetrySenderThread_;
    std::thread heartbeatThread_;
    std::thread driverMonitorThread_;
    std::thread classificationScanThread_;

    // Event queue
    std::queue<Event> eventQueue_;
    std::mutex eventQueueMutex_;
    std::condition_variable eventQueueCondition_;

    // Configuration
    std::string configPath_;
    std::string backendUrl_;
    std::string agentId_;
    std::string policyPath_;

    // Internal methods
    void EventLoop();
    void RefreshPolicy();
    void SendTelemetry();
    void SendHeartbeatLoop();
    bool ValidateConfiguration();
    void ProcessEvent(const Event& event);

    // Kernel driver integration
    void OnKernelBlockEvent(const struct _DLP_EVENT_NOTIFICATION& event);
    void DriverMonitorLoop();
    void InitializeKernelIntegration();
    void StartClassificationScan();
};
