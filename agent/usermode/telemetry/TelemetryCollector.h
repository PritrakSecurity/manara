#pragma once

#include "../core/EventTypes.h"
#include <vector>
#include <thread>
#include <queue>
#include <mutex>
#include <atomic>
#include <windows.h>
#include <unordered_set>
#include <string>

// Forward declaration
class QuarantineManager;

/**
 * Telemetry Collector
 * Monitors system events (file system, USB, network, clipboard) and collects them for policy evaluation
 */
class TelemetryCollector {
public:
    TelemetryCollector();
    ~TelemetryCollector();

    /**
     * Start monitoring
     */
    void Start();

    /**
     * Stop monitoring
     */
    void Stop();

    /**
     * Attach the quarantine manager used to move violating files into the
     * protected quarantine store (never destructive deletion).
     */
    void SetQuarantineManager(QuarantineManager* manager);

    /**
     * Collect an event
     * @param event Event to collect
     */
    void CollectEvent(const Event& event);

    /**
     * Get batch of events
     * @param maxSize Maximum number of events to return
     * @return Vector of events
     */
    std::vector<Event> GetBatch(size_t maxSize);

private:
    // Monitoring threads
    void MonitorLoop();
    void MonitorFileSystem();
    void MonitorUSB();
    void MonitorNetwork();
    void MonitorClipboard();

    // Event queue
    std::queue<Event> eventQueue_;
    std::mutex queueMutex_;
    std::atomic<bool> running_;
    std::thread monitorThread_;

    // Windows-specific handles
    HANDLE fileSystemHandle_;
    HANDLE usbNotificationHandle_;

    // Simple seen file cache for polling-based removable-media detection
    std::unordered_set<std::string> seenFiles_;
    std::mutex seenFilesMutex_;

    // Non-owning quarantine manager (never deletes files)
    QuarantineManager* quarantineManager_;
};
