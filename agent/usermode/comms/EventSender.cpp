#include "EventSender.h"
#include "HttpClient.h"

#include <sstream>
#include <iomanip>
#include <algorithm>

// JSON escaping helper
static std::string JsonEscape(const std::string& s) {
    std::ostringstream o;
    for (char c : s) {
        switch (c) {
            case '"': o << "\\\""; break;
            case '\\': o << "\\\\"; break;
            case '\b': o << "\\b"; break;
            case '\f': o << "\\f"; break;
            case '\n': o << "\\n"; break;
            case '\r': o << "\\r"; break;
            case '\t': o << "\\t"; break;
            default:
                if ('\x00' <= c && c <= '\x1f') {
                    o << "\\u" << std::hex << std::setw(4) << std::setfill('0') << (int)(unsigned char)c;
                } else {
                    o << c;
                }
        }
    }
    return o.str();
}

EventSender::EventSender()
    : isRunning_(false)
    , batchSize_(50)
    , batchTimeoutMs_(5000)
    , totalEventsSent_(0)
    , totalEventsFailed_(0)
{
    httpClient_ = std::make_unique<HttpClient>();
}

EventSender::~EventSender() {
    Stop();
}

bool EventSender::Initialize(const std::string& backendUrl, const std::string& deviceId) {
    deviceId_ = deviceId;
    httpClient_->SetBaseUrl(backendUrl);
    return true;
}

void EventSender::SetAuthToken(const std::string& token) {
    httpClient_->SetAuthToken(token);
}

void EventSender::SetCaCertificatePath(const std::string& caCertPath) {
    httpClient_->SetCaCertificatePath(caCertPath);
}

void EventSender::Start(int batchSize, int batchTimeoutMs) {
    if (isRunning_) return;
    
    batchSize_ = batchSize;
    batchTimeoutMs_ = batchTimeoutMs;
    isRunning_ = true;
    
    senderThread_ = std::thread(&EventSender::SenderLoop, this);
}

void EventSender::Stop() {
    isRunning_ = false;
    queueCondition_.notify_all();
    
    if (senderThread_.joinable()) {
        senderThread_.join();
    }
    
    // Flush remaining events
    Flush();
}

void EventSender::QueueEvent(const TelemetryEvent& event) {
    {
        std::lock_guard<std::mutex> lock(queueMutex_);
        eventQueue_.push(event);
    }
    queueCondition_.notify_one();
}

size_t EventSender::GetPendingCount() const {
    std::lock_guard<std::mutex> lock(queueMutex_);
    return eventQueue_.size();
}

void EventSender::Flush() {
    std::vector<TelemetryEvent> batch;
    
    {
        std::lock_guard<std::mutex> lock(queueMutex_);
        while (!eventQueue_.empty()) {
            batch.push_back(eventQueue_.front());
            eventQueue_.pop();
            
            if ((int)batch.size() >= batchSize_) {
                SendBatch(batch);
                batch.clear();
            }
        }
    }
    
    if (!batch.empty()) {
        SendBatch(batch);
    }
}

void EventSender::SetStatusCallback(std::function<void(bool, int)> callback) {
    statusCallback_ = callback;
}

void EventSender::SenderLoop() {
    while (isRunning_) {
        std::vector<TelemetryEvent> batch;
        
        {
            std::unique_lock<std::mutex> lock(queueMutex_);
            
            // Wait for events or timeout
            queueCondition_.wait_for(lock, std::chrono::milliseconds(batchTimeoutMs_), [this] {
                return !eventQueue_.empty() || !isRunning_;
            });
            
            if (!isRunning_ && eventQueue_.empty()) break;
            
            // Collect batch
            while (!eventQueue_.empty() && (int)batch.size() < batchSize_) {
                batch.push_back(eventQueue_.front());
                eventQueue_.pop();
            }
        }
        
        if (!batch.empty()) {
            SendBatch(batch);
        }
    }
}

bool EventSender::SendBatch(const std::vector<TelemetryEvent>& batch) {
    if (batch.empty()) return true;
    
    std::string payload = SerializeBatch(batch);
    
    HttpClient::Response response = httpClient_->Post("/api/v1/events/batch", payload);
    
    if (response.success) {
        totalEventsSent_ += batch.size();
        
        if (statusCallback_) {
            statusCallback_(true, (int)batch.size());
        }
        return true;
    } else {
        totalEventsFailed_ += batch.size();
        
        if (statusCallback_) {
            statusCallback_(false, (int)batch.size());
        }
        
        // TODO: Cache failed events for retry
        return false;
    }
}

std::string EventSender::SerializeBatch(const std::vector<TelemetryEvent>& batch) {
    std::ostringstream json;
    json << "{\"device_id\":\"" << JsonEscape(deviceId_) << "\",\"events\":[";
    
    bool first = true;
    for (const auto& event : batch) {
        if (!first) json << ",";
        first = false;
        json << SerializeEvent(event);
    }
    
    json << "]}";
    return json.str();
}

std::string EventSender::SerializeEvent(const TelemetryEvent& event) {
    // Convert timestamp to ISO 8601
    auto time = std::chrono::system_clock::to_time_t(event.timestamp);
    std::tm tm = *std::gmtime(&time);
    std::ostringstream timestamp;
    timestamp << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    
    std::ostringstream json;
    json << "{"
         << "\"event_type\":\"" << JsonEscape(event.eventType) << "\","
         << "\"file_path\":\"" << JsonEscape(event.filePath) << "\","
         << "\"file_name\":\"" << JsonEscape(event.fileName) << "\","
         << "\"username\":\"" << JsonEscape(event.username) << "\","
         << "\"process_name\":\"" << JsonEscape(event.processName) << "\","
         << "\"classification\":\"" << JsonEscape(event.classification) << "\","
         << "\"risk_level\":\"" << JsonEscape(event.riskLevel) << "\","
         << "\"classification_score\":" << event.classificationScore << ","
         << "\"file_size\":" << event.fileSize << ","
         << "\"was_blocked\":" << (event.wasBlocked ? "true" : "false") << ","
         << "\"block_reason\":\"" << JsonEscape(event.blockReason) << "\","
         << "\"timestamp\":\"" << timestamp.str() << "\","
         << "\"keywords_found\":[";
    
    bool first = true;
    for (const auto& kw : event.keywordsFound) {
        if (!first) json << ",";
        first = false;
        json << "\"" << JsonEscape(kw) << "\"";
    }
    
    json << "]}";
    return json.str();
}
