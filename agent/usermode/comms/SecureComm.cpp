#include "SecureComm.h"
#include "HttpClient.h"
#include "../core/EventTypes.h"
#include "../../common/utils/logging.h"
#include "../../common/utils/NetworkUtils.h"
#include "../../common/config/Config.h"

#include <sstream>
#include <chrono>
#include <ctime>
#include <nlohmann/json.hpp>

SecureComm::SecureComm()
    : isConnected_(false)
{
}

SecureComm::~SecureComm() {
    Disconnect();
}

bool SecureComm::ParseBackendUrl(const std::string& url) {
    size_t protocolEnd = url.find("://");
    if (protocolEnd == std::string::npos) {
        LOG_ERROR("Invalid server URL format: %s", url.c_str());
        return false;
    }

    // Normalize gRPC-style schemes to plain HTTPS for the REST API.
    std::string work = url;
    if (work.substr(0, 8) == "grpcs://") {
        work = "https://" + work.substr(8);
    } else if (work.substr(0, 7) == "grpc://") {
        work = "http://" + work.substr(7);
    }

    std::string hostPort = work.substr(work.find("://") + 3);
    size_t colonPos = hostPort.find(':');
    if (colonPos != std::string::npos) {
        size_t slashPos = hostPort.find('/');
        std::string hostPart = hostPort.substr(0, slashPos == std::string::npos ? colonPos : slashPos);
        serverHost_ = hostPart;
    } else {
        serverHost_ = hostPort;
    }

    serverUrl_ = work;
    return true;
}

bool SecureComm::Initialize(const std::string& serverUrl, const std::string& certPath) {
    std::lock_guard<std::mutex> lock(stateMutex_);

    serverUrl_ = serverUrl;
    caCertPath_ = certPath;

    if (!ParseBackendUrl(serverUrl)) {
        return false;
    }

    httpClient_ = std::make_unique<HttpClient>();
    httpClient_->SetBaseUrl(serverUrl_);
    httpClient_->SetTimeout(30000);

    // Only require a CA certificate when talking TLS (https / grpcs). Plain
    // HTTP needs no certificate and must NOT fail when ca.crt is absent.
    // (ParseBackendUrl already normalized grpcs:// -> https:// above.)
    const bool isHttps = (serverUrl_.find("https://") == 0);
    if (isHttps) {
        if (caCertPath_.empty() || !httpClient_->SetCaCertificatePath(caCertPath_)) {
            LOG_ERROR("Failed to load CA certificate for TLS validation: %s", caCertPath_.c_str());
            return false;
        }
    } else {
        LOG_INFO("Using plain HTTP transport (no TLS/CA certificate required)");
    }

    return true;
}

bool SecureComm::EstablishConnection() {
    // Perform a handshake round-trip to force TLS validation. If the server
    // certificate does not chain to the configured CA the request fails and
    // the agent stays disconnected.
    HttpClient::Response response = httpClient_->Get("/api/health");

    if (!response.success) {
        LOG_WARNING("TLS handshake/health check failed: %s", response.error.c_str());
        isConnected_.store(false);
        return false;
    }

    isConnected_.store(true);
    LOG_INFO("Connected to backend: %s", serverHost_.c_str());
    return true;
}

bool SecureComm::Connect() {
    std::lock_guard<std::mutex> lock(stateMutex_);

    if (isConnected_.load()) {
        return true;
    }

    if (!httpClient_) {
        LOG_ERROR("SecureComm not initialized");
        return false;
    }

    return EstablishConnection();
}

void SecureComm::Disconnect() {
    isConnected_.store(false);
    // The WinHTTP session remains alive but no connection is outstanding.
}

void SecureComm::SetAuthToken(const std::string& token) {
    if (httpClient_) {
        httpClient_->SetAuthToken(token);
    }
}

bool SecureComm::SendEvents(const std::vector<Event>& events) {
    if (!isConnected_.load() || !httpClient_) {
        return false;
    }

    if (events.empty()) {
        return true;
    }

    // Build an EventBatch payload compatible with /api/v1/events/batch.
    std::ostringstream json;
    json << "{\"device_id\":\"";
    if (!events.empty() && !events.front().agentId.empty()) {
        json << events.front().agentId;
    }
    json << "\",\"events\":[";

    bool first = true;
    for (const auto& event : events) {
        if (!first) {
            json << ",";
        }
        first = false;

        auto time = std::chrono::system_clock::to_time_t(event.timestamp);
        std::tm tm = *std::gmtime(&time);
        char ts[32] = {0};
        std::strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &tm);

        json << "{"
             << "\"event_type\":\"" << static_cast<int>(event.type) << "\","
             << "\"file_path\":\"" << event.filePath << "\","
             << "\"process_name\":\"" << event.processName << "\","
             << "\"username\":\"" << event.userId << "\","
             << "\"classification\":\"UNKNOWN\","
             << "\"risk_level\":\"NONE\","
             << "\"classification_score\":0,"
             << "\"operation_result\":\"blocked\","
             << "\"timestamp\":\"" << ts << "\""
             << "}";
    }

    json << "]}";

    HttpClient::Response response = httpClient_->Post("/api/v1/events/batch", json.str());

    if (!response.success) {
        LOG_WARNING("Failed to send events to backend: %s", response.error.c_str());
        return false;
    }

    return true;
}

std::string SecureComm::FetchPolicy() {
    if (!isConnected_.load() || !httpClient_) {
        return "";
    }

    HttpClient::Response response = httpClient_->Get("/api/policies");
    if (!response.success) {
        LOG_WARNING("Failed to fetch policy: %s", response.error.c_str());
        return "";
    }

    return response.body;
}

bool SecureComm::SendHeartbeat() {
    if (!isConnected_.load() || !httpClient_) {
        return false;
    }

    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::tm tm = *std::gmtime(&time);
    char ts[32] = {0};
    std::strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &tm);

    std::ostringstream json;
    json << "{\"device_id\":\"agent\",\"hostname\":\"unknown\",\"status\":\"online\",\"timestamp\":\"" << ts << "\"}";

    HttpClient::Response response = httpClient_->Post("/api/devices/heartbeat", json.str());

    if (!response.success) {
        LOG_WARNING("Heartbeat failed: %s", response.error.c_str());
        return false;
    }

    return true;
}

bool SecureComm::RegisterDevice(const std::string& serverUrl,
                                const std::string& hostname,
                                const std::string& osVersion,
                                const std::string& agentVersion,
                                std::string& outToken,
                                std::string& outDeviceId) {
    HttpClient client;
    client.SetBaseUrl(serverUrl);
    client.SetTimeout(15000);

    nlohmann::json payload;
    payload["hostname"] = hostname;
    payload["ipAddress"] = NetworkUtils::GetPrimaryIPv4Address();
    payload["osVersion"] = osVersion;
    payload["agentVersion"] = agentVersion;
    payload["registrationMethod"] = "manual";

    HttpClient::Response response = client.Post("/api/devices/register", payload.dump());
    if (!response.success || response.statusCode != 200) {
        LOG_WARNING("Device registration failed: %s (status %d)", response.error.c_str(), response.statusCode);
        return false;
    }

    try {
        nlohmann::json json = nlohmann::json::parse(response.body);
        if (json.contains("token")) {
            outToken = json["token"].get<std::string>();
        }
        if (json.contains("deviceId")) {
            outDeviceId = json["deviceId"].get<std::string>();
        } else if (json.contains("device_id")) {
            outDeviceId = json["device_id"].get<std::string>();
        } else if (json.contains("agent_id")) {
            outDeviceId = json["agent_id"].get<std::string>();
        }
    } catch (const std::exception&) {
        LOG_WARNING("Device registration response was not valid JSON");
        return false;
    }

    if (outToken.empty() || outDeviceId.empty()) {
        LOG_WARNING("Device registration response missing token/deviceId");
        return false;
    }

    // Persist the enrolled agent/device id so it survives reboots.
    Config::GetInstance().SetAgentId(outDeviceId);

    LOG_INFO("Device enrolled with backend: id=%s", outDeviceId.c_str());
    return true;
}

bool SecureComm::SendInventoryUpdate(const std::string& payloadJson) {
    HttpClient client;
    client.SetBaseUrl(Config::GetInstance().GetBackendUrl());
    client.SetTimeout(15000);

    // Standard Authorization: Bearer <token> header on every request.
    const std::string token = Config::GetInstance().GetAuthToken();
    if (!token.empty()) {
        client.SetAuthToken(token);
    }

    HttpClient::Response response = client.Post("/api/v1/dspm/inventory", payloadJson);
    if (!response.success || response.statusCode != 200) {
        LOG_WARNING("Inventory update failed: %s (status %d)",
            response.error.c_str(), response.statusCode);
        return false;
    }

    return true;
}
