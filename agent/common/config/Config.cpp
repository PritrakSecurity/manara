#include "Config.h"
#include <fstream>
#include <sstream>

Config& Config::GetInstance() {
    static Config instance;
    return instance;
}

bool Config::Load(const std::string& configPath) {
    configPath_ = configPath;
    std::ifstream file(configPath);
    if (!file.is_open()) {
        // Use defaults
        config_ = nlohmann::json::object();
        config_["backend"]["url"] = "grpcs://localhost:50051";
        config_["policy"]["localFallbackPath"] = "C:\\ProgramData\\PritrakDLP\\policy.json";
        config_["telemetry"]["offlineCachePath"] = "C:\\ProgramData\\PritrakDLP\\cache.db";
        loaded_ = true;
        return true;
    }

    try {
        file >> config_;
        loaded_ = true;
        return true;
    } catch (const nlohmann::json::exception& e) {
        loaded_ = false;
        return false;
    }
}

std::string Config::GetBackendUrl() const {
    // New install format writes a top-level "server_url".
    if (config_.contains("server_url") && config_["server_url"].is_string()) {
        return config_["server_url"].get<std::string>();
    }
    if (config_.contains("backend") && config_["backend"].contains("url")) {
        return config_["backend"]["url"].get<std::string>();
    }
    return "grpcs://localhost:50051";
}

std::string Config::GetCertPath() const {
    if (config_.contains("backend") && config_["backend"].contains("mTLS") &&
        config_["backend"]["mTLS"].contains("certPath")) {
        return config_["backend"]["mTLS"]["certPath"].get<std::string>();
    }
    return "C:\\ProgramData\\PritrakDLP\\agent.crt";
}

std::string Config::GetPolicyPath() const {
    if (config_.contains("policy") && config_["policy"].contains("localFallbackPath")) {
        return config_["policy"]["localFallbackPath"].get<std::string>();
    }
    return "C:\\ProgramData\\PritrakDLP\\policy.json";
}

std::string Config::GetCachePath() const {
    if (config_.contains("telemetry") && config_["telemetry"].contains("offlineCachePath")) {
        return config_["telemetry"]["offlineCachePath"].get<std::string>();
    }
    return "C:\\ProgramData\\PritrakDLP\\cache.db";
}

std::string Config::GetLogLevel() const {
    if (config_.contains("logging") && config_["logging"].contains("level")) {
        return config_["logging"]["level"].get<std::string>();
    }
    return "INFO";
}

std::string Config::GetAuthToken() const {
    if (config_.contains("backend") && config_["backend"].contains("authToken")) {
        return config_["backend"]["authToken"].get<std::string>();
    }
    return "";
}

std::string Config::GetAgentId() const {
    if (config_.contains("agent_id") && config_["agent_id"].is_string()) {
        return config_["agent_id"].get<std::string>();
    }
    return "";
}

void Config::Save() {
    if (configPath_.empty()) {
        return;
    }
    std::ofstream file(configPath_, std::ios::trunc);
    if (file.is_open()) {
        file << config_.dump(4);
    }
}

void Config::SetAuthToken(const std::string& token) {
    config_["backend"]["authToken"] = token;
    Save();
}

void Config::SetAgentId(const std::string& agentId) {
    config_["agent_id"] = agentId;
    Save();
}

std::string Config::GetCaCertPath() const {
    if (config_.contains("backend") && config_["backend"].contains("mTLS") &&
        config_["backend"]["mTLS"].contains("caPath")) {
        return config_["backend"]["mTLS"]["caPath"].get<std::string>();
    }
    return "C:\\ProgramData\\PritrakDLP\\ca.crt";
}

int Config::GetHeartbeatIntervalSeconds() const {
    if (config_.contains("heartbeat_interval_sec") && config_["heartbeat_interval_sec"].is_number()) {
        return config_["heartbeat_interval_sec"].get<int>();
    }
    return 30;
}

std::string Config::GetEnforcementMode() const {
    if (config_.contains("enforcement_mode") && config_["enforcement_mode"].is_string()) {
        return config_["enforcement_mode"].get<std::string>();
    }
    return "MONITOR_ONLY";
}
