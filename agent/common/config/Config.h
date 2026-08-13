#pragma once

#include <string>
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

private:
    Config() = default;
    ~Config() = default;
    Config(const Config&) = delete;
    Config& operator=(const Config&) = delete;

    nlohmann::json config_;
    bool loaded_;
    std::string configPath_;
};
