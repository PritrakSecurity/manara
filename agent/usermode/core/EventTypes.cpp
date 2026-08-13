#include "EventTypes.h"
#include <nlohmann/json.hpp>
#include <sstream>
#include <iomanip>

std::string Event::ToJson() const {
    std::stringstream ss;
    ss << "{"
       << "\"type\":\"" << static_cast<int>(type) << "\","
       << "\"agentId\":\"" << agentId << "\","
       << "\"processName\":\"" << processName << "\","
       << "\"filePath\":\"" << filePath << "\","
       << "\"deviceName\":\"" << deviceName << "\","
       << "\"data\":\"" << data << "\","
       << "\"timestamp\":\"" << std::chrono::duration_cast<std::chrono::seconds>(timestamp.time_since_epoch()).count() << "\","
       << "\"severity\":\"" << static_cast<int>(severity) << "\","
       << "\"userId\":\"" << userId << "\","
       << "\"hostname\":\"" << hostname << "\""
       << "}";
    return ss.str();
}

bool Event::FromJson(const std::string& json, Event& out) {
    try {
        auto j = nlohmann::json::parse(json);

        out.type = static_cast<EventType>(j.value("type", static_cast<int>(EventType::FILE_ACCESS)));
        out.agentId = j.value("agentId", std::string());
        out.processName = j.value("processName", std::string());
        out.filePath = j.value("filePath", std::string());
        out.deviceName = j.value("deviceName", std::string());
        out.data = j.value("data", std::string());
        out.userId = j.value("userId", std::string());
        out.hostname = j.value("hostname", std::string());
        out.severity = static_cast<Severity>(j.value("severity", static_cast<int>(Severity::LOW)));

        std::string tsStr = j.value("timestamp", std::string("0"));
        long long epochSeconds = 0;
        try {
            epochSeconds = std::stoll(tsStr);
        } catch (const std::exception&) {
            epochSeconds = 0;
        }
        out.timestamp = std::chrono::system_clock::time_point(
            std::chrono::seconds(epochSeconds));

        return true;
    } catch (const std::exception&) {
        return false;
    }
}
