#pragma once

#include <string>
#include <thread>
#include <atomic>
#include <memory>
#include <functional>

class HttpClient;

/**
 * HeartbeatManager handles periodic heartbeat sending to the backend
 * Uses plain HTTP for reliability - works without TLS configuration
 */
class HeartbeatManager {
public:
    HeartbeatManager();
    ~HeartbeatManager();

    /**
     * Initialize the heartbeat manager
     * @param backendUrl Backend HTTP URL (e.g., "http://localhost:8080")
     * @param deviceId Unique device identifier
     * @param hostname Device hostname
     * @return true if initialized successfully
     */
    bool Initialize(const std::string& backendUrl, 
                    const std::string& deviceId,
                    const std::string& hostname);

    /**
     * Set the authorization bearer token injected on every request
     */
    void SetAuthToken(const std::string& token);

    /**
     * Configure strict TLS validation against the given CA certificate
     */
    void SetCaCertificatePath(const std::string& caCertPath);

    /**
     * Start sending heartbeats
     * @param intervalSeconds Interval between heartbeats (default 30s)
     */
    void Start(int intervalSeconds = 30);

    /**
     * Stop sending heartbeats
     */
    void Stop();

    /**
     * Check if heartbeat manager is running
     */
    bool IsRunning() const { return isRunning_; }

    /**
     * Get the last heartbeat status
     */
    bool WasLastHeartbeatSuccessful() const { return lastHeartbeatSuccess_; }

    /**
     * Get consecutive failure count
     */
    int GetFailureCount() const { return consecutiveFailures_; }

    /**
     * Send a single heartbeat immediately
     * @return true if heartbeat was sent successfully
     */
    bool SendHeartbeatNow();

    /**
     * Set callback for heartbeat status changes
     */
    void SetStatusCallback(std::function<void(bool success, int failures)> callback);

    /**
     * Get device info for heartbeat
     */
    static std::string GetSystemInfo();

private:
    void HeartbeatLoop();
    std::string BuildHeartbeatPayload();

    std::unique_ptr<HttpClient> httpClient_;
    std::thread heartbeatThread_;
    std::atomic<bool> isRunning_;
    std::atomic<bool> lastHeartbeatSuccess_;
    std::atomic<int> consecutiveFailures_;

    std::string backendUrl_;
    std::string deviceId_;
    std::string hostname_;
    std::string ipAddress_;
    std::string osVersion_;
    std::string agentVersion_;

    int intervalSeconds_;
    std::function<void(bool, int)> statusCallback_;
};
