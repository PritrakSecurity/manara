#pragma once

#include <string>
#include <cstddef>
#include <nlohmann/json.hpp>

/**
 * Configuration manager
 * Loads and manages agent configuration from JSON file
 */
class Config {
public:
    static Config& GetInstance();

    /**
     * Load configuration from file
     * @param configPath Path to configuration file
     * @return true if loaded successfully, false otherwise
     */
    bool Load(const std::string& configPath);

    /**
     * Get backend URL
     */
    std::string GetBackendUrl() const;

    /**
     * Get certificate path
     */
    std::string GetCertPath() const;

    /**
     * Get the CA certificate path used for strict server validation
     */
    std::string GetCaCertPath() const;

    /**
     * Get policy path
     */
    std::string GetPolicyPath() const;

    /**
     * Get cache path
     */
    std::string GetCachePath() const;

    /**
     * Get log level
     */
    std::string GetLogLevel() const;

    /**
     * Get the backend authentication bearer token (may be empty)
     */
    std::string GetAuthToken() const;

    /**
     * Get the persisted enrolled agent/device id (may be empty)
     */
    std::string GetAgentId() const;

    /**
     * Persist the device enrollment bearer token into the configuration file
     * so it survives reboots.
     */
    void SetAuthToken(const std::string& token);

    /**
     * Persist the enrolled agent/device id into the configuration file so it
     * survives reboots.
     */
    void SetAgentId(const std::string& agentId);

    /**
     * Write the current configuration back to the configuration file.
     */
    void Save();

    /**
     * Get the heartbeat interval in seconds (default 30)
     */
    int GetHeartbeatIntervalSeconds() const;

    /**
     * Get the enforcement mode ("MONITOR_ONLY" or "ENFORCE"). Defaults to
     * "MONITOR_ONLY" (fail-safe) when not configured.
     */
    std::string GetEnforcementMode() const;

    // ------------------------------------------------------------------
    // Phase 1 Clipboard Visibility configuration (detection-only).
    // Conservative defaults; invalid values are rejected by the consumer and
    // replaced with defaults (see ValidateClipboardConfig in ClipboardMonitor).
    // ------------------------------------------------------------------

    /** Whether clipboard visibility is enabled (default true). */
    bool GetClipboardMonitoringEnabled() const;

    /** Maximum clipboard text to capture, in UTF-16 bytes (default 256 KiB). */
    size_t GetClipboardMaxUtf16Bytes() const;

    /** Bounded clipboard-open retry count (default 5). */
    int GetClipboardOpenRetryCount() const;

    /** Delay between clipboard-open retries in ms (default 50). */
    int GetClipboardOpenRetryDelayMs() const;

    /** Maximum queued clipboard events (latest-value slots; default 1). */
    size_t GetClipboardMaxQueuedEvents() const;

    /** Classification timeout guard in ms (default 2000). */
    int GetClipboardScanTimeoutMs() const;

private:
    Config() = default;
    ~Config() = default;
    Config(const Config&) = delete;
    Config& operator=(const Config&) = delete;

    nlohmann::json config_;
    bool loaded_;
    std::string configPath_;
};
