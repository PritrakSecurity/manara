#pragma once

#include <string>
#include <vector>
#include <queue>
#include <mutex>
#include <thread>
#include <atomic>
#include <memory>
#include <functional>
#include <chrono>

class HttpClient;

/**
 * Event structure for telemetry data
 */
struct TelemetryEvent {
    std::string eventType;      // file_created, file_modified, file_deleted, etc.
    std::string filePath;
    std::string fileName;
    std::string username;
    std::string processName;
    std::string classification; // PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED
    std::string riskLevel;      // NONE, LOW, MEDIUM, HIGH, CRITICAL
    double classificationScore;
    std::vector<std::string> keywordsFound;
    std::chrono::system_clock::time_point timestamp;
    int64_t fileSize;
    bool wasBlocked;
    std::string blockReason;
};

/**
 * EventSender handles batching and sending events to the backend
 * Supports offline caching and automatic retry
 */
class EventSender {
public:
    EventSender();
    ~EventSender();

    /**
     * Initialize the event sender
     * @param backendUrl Backend HTTP URL
     * @param deviceId Device identifier
     * @return true if initialized successfully
     */
    bool Initialize(const std::string& backendUrl, const std::string& deviceId);

    /**
     * Set the authorization bearer token injected on every request
     */
    void SetAuthToken(const std::string& token);

    /**
     * Configure strict TLS validation against the given CA certificate
     */
    void SetCaCertificatePath(const std::string& caCertPath);

    /**
     * Start the event sender background thread
     * @param batchSize Maximum events per batch
     * @param batchTimeoutMs Maximum wait time before sending a batch
     */
    void Start(int batchSize = 50, int batchTimeoutMs = 5000);

    /**
     * Stop the event sender
     */
    void Stop();

    /**
     * Queue an event for sending
     * @param event The event to send
     */
    void QueueEvent(const TelemetryEvent& event);

    /**
     * Get pending event count
     */
    size_t GetPendingCount() const;

    /**
     * Get total events sent
     */
    int64_t GetTotalEventsSent() const { return totalEventsSent_; }

    /**
     * Get total events failed
     */
    int64_t GetTotalEventsFailed() const { return totalEventsFailed_; }

    /**
     * Force flush pending events now
     */
    void Flush();

    /**
     * Set callback for send status
     */
    void SetStatusCallback(std::function<void(bool success, int count)> callback);

private:
    void SenderLoop();
    bool SendBatch(const std::vector<TelemetryEvent>& batch);
    std::string SerializeBatch(const std::vector<TelemetryEvent>& batch);
    std::string SerializeEvent(const TelemetryEvent& event);

    std::unique_ptr<HttpClient> httpClient_;
    std::thread senderThread_;
    std::atomic<bool> isRunning_;
    
    std::queue<TelemetryEvent> eventQueue_;
    mutable std::mutex queueMutex_;
    std::condition_variable queueCondition_;
    
    std::string deviceId_;
    int batchSize_;
    int batchTimeoutMs_;
    
    std::atomic<int64_t> totalEventsSent_;
    std::atomic<int64_t> totalEventsFailed_;
    
    std::function<void(bool, int)> statusCallback_;
};
