#define INITGUID
#include "TelemetryCollector.h"
#include "ClipboardMonitor.h"
#include "../quarantine/QuarantineManager.h"
#include "../../common/utils/logging.h"
#include "../../common/config/Config.h"
#include <windows.h>
#include <setupapi.h>
#include <usbiodef.h>
#include <wininet.h>
#include <iphlpapi.h>
#include <chrono>
#include <sstream>
#include <filesystem>
#include <vector>
#include <algorithm>
#include <cctype>

// Returns true if a file path looks potentially sensitive (credentials,
// certificates, private keys, financial/spreadsheet data). Used to gate
// telemetry events so the agent does not upload an event for EVERY file
// create/modify/delete operation.
static bool IsPotentiallySensitive(const std::string& path) {
    std::string lower = path;
    std::transform(lower.begin(), lower.end(), lower.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    // Filename keyword check (credentials / secrets).
    const char* sensitiveNames[] = {
        "password", "secret", "credential", "private_key", "id_rsa",
        "id_dsa", "id_ecdsa", ".gitconfig", ".htpasswd", "token", "apikey"
    };
    for (const char* kw : sensitiveNames) {
        if (lower.find(kw) != std::string::npos) {
            return true;
        }
    }

    // Sensitive extension check (certificates, keys, DBs, financial exports).
    const char* sensitiveExts[] = {
        ".key", ".pem", ".pfx", ".p12", ".cer", ".crt", ".der", ".jks", ".keystore",
        ".env", ".htpasswd", ".sql", ".sqlite", ".sqlite3", ".db",
        ".csv", ".xls", ".xlsx"
    };
    size_t dot = lower.rfind('.');
    if (dot != std::string::npos) {
        std::string ext = lower.substr(dot);
        for (const char* e : sensitiveExts) {
            if (ext == e) {
                return true;
            }
        }
    }
    return false;
}

TelemetryCollector::TelemetryCollector()
    : running_(false)
    , fileSystemHandle_(INVALID_HANDLE_VALUE)
    , usbNotificationHandle_(INVALID_HANDLE_VALUE)
    , quarantineManager_(nullptr)
{
}

void TelemetryCollector::SetQuarantineManager(QuarantineManager* manager) {
    quarantineManager_ = manager;
}

TelemetryCollector::~TelemetryCollector() {
    Stop();
}

void TelemetryCollector::Start() {
    if (running_) {
        return;
    }

    running_ = true;
    monitorThread_ = std::thread(&TelemetryCollector::MonitorLoop, this);
    StartClipboardMonitoring();
    LOG_INFO("Telemetry collector started");
}

void TelemetryCollector::Stop() {
    if (!running_) {
        return;
    }

    running_ = false;

    // Stop clipboard visibility first: joins its listener + worker threads so
    // no callback can touch collector-owned objects afterwards.
    if (clipboardMonitor_) {
        clipboardMonitor_->Stop();
        clipboardMonitor_.reset();
    }

    if (monitorThread_.joinable()) {
        monitorThread_.join();
    }

    if (fileSystemHandle_ != INVALID_HANDLE_VALUE) {
        CloseHandle(fileSystemHandle_);
        fileSystemHandle_ = INVALID_HANDLE_VALUE;
    }

    if (usbNotificationHandle_ != INVALID_HANDLE_VALUE) {
        CloseHandle(usbNotificationHandle_);
        usbNotificationHandle_ = INVALID_HANDLE_VALUE;
    }

    LOG_INFO("Telemetry collector stopped");
}

void TelemetryCollector::CollectEvent(const Event& event) {
    // Data-quality gate: only queue events for potentially sensitive files.
    // Normal text files, caches and everyday documents are ignored locally so
    // the agent does not flood the backend with non-DLP events.
    if (!event.filePath.empty() && !IsPotentiallySensitive(event.filePath)) {
        LOG_DEBUG("Ignoring non-sensitive file event: %s", event.filePath.c_str());
        return;
    }
    std::lock_guard<std::mutex> lock(queueMutex_);
    eventQueue_.push(event);
}

std::vector<Event> TelemetryCollector::GetBatch(size_t maxSize) {
    std::lock_guard<std::mutex> lock(queueMutex_);
    std::vector<Event> batch;

    while (!eventQueue_.empty() && batch.size() < maxSize) {
        batch.push_back(eventQueue_.front());
        eventQueue_.pop();
    }

    return batch;
}

void TelemetryCollector::MonitorLoop() {
    while (running_) {
        MonitorFileSystem();
        MonitorUSB();
        MonitorNetwork();

        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }
}

void TelemetryCollector::MonitorFileSystem() {
    // Poll removable drives only. We MUST NEVER scan fixed drives (C:\ etc.)
    // - walking the system volume spams the log and trips AV/EDR heuristics.
    try {
        // Gather drive letters
        DWORD drives = GetLogicalDrives();
        for (int i = 0; i < 26; ++i) {
            if (!(drives & (1 << i))) continue;
            char driveRoot[] = "A:\\\\"; // placeholder
            driveRoot[0] = 'A' + i;
            UINT type = GetDriveTypeA(driveRoot);
            // DRIVE_REMOVABLE == 2. Only removable media is monitored.
            if (type != DRIVE_REMOVABLE) continue;

            std::string root(driveRoot);
            // Walk the removable drive
            std::filesystem::recursive_directory_iterator it(
                root, std::filesystem::directory_options::skip_permission_denied);
            std::filesystem::recursive_directory_iterator end;
            while (it != end) {
                try {
                    std::string path = it->path().string();

                    // NEVER scan the agent's own installation/data directories
                    // (C:\Program Files\PritrakDLP, C:\ProgramData\PritrakDLP).
                    if (path.find("PritrakDLP") != std::string::npos) {
                        if (it->is_directory()) {
                            it.disable_recursion_pending();
                        }
                        ++it;
                        continue;
                    }

                    if (!it->is_regular_file()) {
                        ++it;
                        continue;
                    }

                    {
                        std::lock_guard<std::mutex> lk(seenFilesMutex_);
                        if (seenFiles_.find(path) != seenFiles_.end()) {
                            ++it;
                            continue;
                        }
                        seenFiles_.insert(path);
                    }

                    // New file detected on removable drive - basic policy check by extension
                    std::string ext = it->path().extension().string();
                    std::vector<std::string> blocked = {".pdf", ".xlsx", ".xls", ".txt", ".doc", ".docx", ".ppt", ".pptx", ".csv", ".json", ".xml", ".png", ".jpg", ".jpeg"};
                    for (const auto& be : blocked) {
                        if (_stricmp(ext.c_str(), be.c_str()) == 0) {
                            // Respect MONITOR_ONLY: never quarantine, only log.
                            if (Config::GetInstance().GetEnforcementMode() == "MONITOR_ONLY") {
                                LOG_INFO("MONITOR_ONLY: Would have quarantined file %s but skipping.", path.c_str());
                            } else if (quarantineManager_ != nullptr) {
                                std::wstring widePath(path.begin(), path.end());
                                quarantineManager_->QuarantineFile(
                                    widePath, L"RESTRICTED", L"", L"blocked extension on removable media");
                            } else {
                                LOG_WARNING("TelemetryCollector: quarantine manager not available; blocked file left in place: %s", path.c_str());
                            }

                            // Create event and queue it for telemetry
                            Event ev;
                            ev.type = EventType::USB_FILE_WRITE;
                            ev.agentId = ""; // agent ID unknown here
                            ev.filePath = path;
                            ev.timestamp = std::chrono::system_clock::now();
                            ev.severity = Severity::HIGH;
                            CollectEvent(ev);
                            break;
                        }
                    }
                    ++it;
                } catch (...) {
                    // Skip inaccessible/locked files instead of crashing the
                    // monitor loop.
                    try {
                        it.disable_recursion_pending();
                    } catch (...) {}
                    ++it;
                }
            }
        }
    } catch (const std::exception& ex) {
        LOG_WARNING("MonitorFileSystem exception: %s", ex.what());
    }
}

void TelemetryCollector::MonitorUSB() {
    // USB device monitoring via SetupAPI
    HDEVINFO deviceInfoSet = SetupDiGetClassDevsA(
        &GUID_DEVINTERFACE_USB_DEVICE,
        NULL,
        NULL,
        DIGCF_PRESENT | DIGCF_DEVICEINTERFACE
    );

    if (deviceInfoSet == INVALID_HANDLE_VALUE) {
        return;
    }

    SP_DEVICE_INTERFACE_DATA deviceInterfaceData;
    deviceInterfaceData.cbSize = sizeof(SP_DEVICE_INTERFACE_DATA);

    for (DWORD i = 0; SetupDiEnumDeviceInterfaces(deviceInfoSet, NULL, &GUID_DEVINTERFACE_USB_DEVICE, i, &deviceInterfaceData); i++) {
        // Detect USB device insertion/removal
        // Create event and queue it
    }

    SetupDiDestroyDeviceInfoList(deviceInfoSet);
}

void TelemetryCollector::MonitorNetwork() {
    // Network flow monitoring via WMI or direct socket inspection
    // Simplified implementation
}

void TelemetryCollector::StartClipboardMonitoring() {
    // Phase 1 Clipboard Visibility (detection-only). Runs on a dedicated
    // listener thread + worker thread owned by ClipboardMonitor. Only active
    // in interactive (non-Session-0) sessions; in Session 0 it logs a
    // privacy-safe warning and stays disabled (see ClipboardMonitor.cpp).
    namespace dlp = Pritrak::DLP;

    dlp::ClipboardConfig cfg;
    cfg.enabled = Config::GetInstance().GetClipboardMonitoringEnabled();
    cfg.maxUtf16Bytes = static_cast<size_t>(Config::GetInstance().GetClipboardMaxUtf16Bytes());
    cfg.openRetryCount = Config::GetInstance().GetClipboardOpenRetryCount();
    cfg.openRetryDelayMs = Config::GetInstance().GetClipboardOpenRetryDelayMs();
    cfg.maxQueuedEvents = static_cast<size_t>(Config::GetInstance().GetClipboardMaxQueuedEvents());
    cfg.scanTimeoutMs = Config::GetInstance().GetClipboardScanTimeoutMs();

    clipboardMonitor_ = std::make_unique<dlp::ClipboardMonitor>();
    clipboardMonitor_->Configure(cfg);
    if (!clipboardMonitor_->Start()) {
        LOG_INFO("Clipboard monitoring is not active in this session");
    }
}
