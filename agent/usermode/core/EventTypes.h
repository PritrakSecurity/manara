#pragma once

#include <string>
#include <chrono>
#include <vector>

/**
 * Event types that the agent monitors
 */
enum class EventType {
    FILE_ACCESS,
    FILE_WRITE,
    USB_CONNECT,
    USB_FILE_WRITE,
    NETWORK_FLOW,
    CLIPBOARD_READ,
    CLIPBOARD_WRITE
};

/**
 * Actions that can be taken on events
 */
enum class Action {
    ALLOW = 0,
    BLOCK = 1,
    LOG = 2,
    ALERT = 3
};

/**
 * Severity levels for events
 */
enum class Severity {
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
};

/**
 * Event structure representing a monitored operation
 */
struct Event {
    EventType type;
    std::string agentId;
    std::string processName;
    std::string filePath;
    std::string deviceName;  // USB/network device
    std::string data;
    std::chrono::system_clock::time_point timestamp;
    Severity severity;
    std::string userId;
    std::string hostname;

    // Convert to JSON string for transmission
    std::string ToJson() const;

    // Deserialize an Event from its ToJson() representation.
    // @return true if the payload parsed successfully, false otherwise.
    static bool FromJson(const std::string& json, Event& out);
};

/**
 * Policy decision result
 */
struct PolicyDecision {
    Action action;
    std::string ruleId;
    std::string reason;
    bool logged;
};
