/**
 * @file KernelComm.cpp
 * @brief User-mode communication with DLP kernel driver - Implementation
 * 
 * PRITRAK Enterprise DLP Agent - Kernel Communication Layer
 * 
 * Copyright (C) 2026 Pritrak Security
 */

#include "KernelComm.h"
#include <fltUser.h>
#include <winioctl.h>
#include <sstream>
#include <chrono>

// For logging
#include "../../common/utils/logging.h"

namespace Pritrak {
namespace DLP {

// ============================================================================
// SINGLETON IMPLEMENTATION
// ============================================================================

KernelComm& KernelComm::GetInstance() {
    static KernelComm instance;
    return instance;
}

KernelComm::KernelComm()
    : m_commandPort(INVALID_HANDLE_VALUE)
    , m_notifyPort(INVALID_HANDLE_VALUE)
    , m_connected(false)
    , m_shutdownRequested(false)
    , m_reconnectAttempts(0)
{
}

KernelComm::~KernelComm() {
    Shutdown();
}

// ============================================================================
// INITIALIZATION AND SHUTDOWN
// ============================================================================

bool KernelComm::Initialize() {
    if (m_connected.load()) {
        LOG_WARNING("KernelComm already initialized");
        return true;
    }

    // If a notification thread is already running it handles reconnection on
    // its own; never spawn a duplicate thread.
    if (m_notifyThread && m_notifyThread->joinable()) {
        return m_connected.load();
    }

    LOG_INFO("Initializing kernel communication...");

    if (!ConnectToDriver()) {
        LOG_ERROR("Failed to connect to kernel driver");
        return false;
    }

    m_shutdownRequested.store(false);

    // Start notification thread
    m_notifyThread = std::make_unique<std::thread>(&KernelComm::NotificationThread, this);

    LOG_INFO("Kernel communication initialized successfully");
    return true;
}

void KernelComm::Shutdown() {
    LOG_INFO("Shutting down kernel communication...");

    m_shutdownRequested.store(true);

    // Close the ports FIRST so a blocked FilterGetMessage returns and the
    // notification thread can observe the shutdown flag (otherwise join
    // would deadlock waiting on an indefinite read).
    DisconnectFromDriver();

    // Wait for notification thread with a 5-second timeout. If it doesn't
    // exit, log a warning — the join will still block, but since the ports
    // are already closed FilterGetMessage should return within milliseconds.
    if (m_notifyThread && m_notifyThread->joinable()) {
        HANDLE hThread = m_notifyThread->native_handle();
        if (hThread != nullptr) {
            DWORD waitResult = WaitForSingleObject(hThread, 5000);
            if (waitResult == WAIT_TIMEOUT) {
                LOG_WARNING("KernelComm: notification thread did not exit within 5s");
            }
        }
        m_notifyThread->join();
        m_notifyThread.reset();
    }

    LOG_INFO("Kernel communication shutdown complete");
}

bool KernelComm::IsConnected() const {
    return m_connected.load();
}

// ============================================================================
// DRIVER CONNECTION
// ============================================================================

bool KernelComm::ConnectToDriver() {
    HRESULT hr;

    if (m_commandPort != INVALID_HANDLE_VALUE) {
        CloseHandle(m_commandPort);
        m_commandPort = INVALID_HANDLE_VALUE;
    }
    if (m_notifyPort != INVALID_HANDLE_VALUE) {
        CloseHandle(m_notifyPort);
        m_notifyPort = INVALID_HANDLE_VALUE;
    }

    // Connect to the command port (usermode -> kernel policy/config).
    hr = FilterConnectCommunicationPort(
        DLP_COMMAND_PORT_NAME,
        0,                          // Options
        nullptr,                    // Context
        0,                          // Context size
        nullptr,                    // Security attributes
        &m_commandPort
    );

    if (FAILED(hr)) {
        LOG_ERROR("Failed to connect to command port: 0x%08X", hr);
        m_commandPort = INVALID_HANDLE_VALUE;
        return false;
    }

    // Connect to the notification port (kernel -> usermode block events).
    // The port ACL restricts access to NT AUTHORITY\SYSTEM, which is the
    // account the SCM-hosted service runs under.
    hr = FilterConnectCommunicationPort(
        DLP_NOTIFICATION_PORT_NAME,
        0,                          // Options
        nullptr,                    // Context
        0,                          // Context size
        nullptr,                    // Security attributes
        &m_notifyPort
    );

    if (FAILED(hr)) {
        LOG_WARNING("Failed to connect to notify port: 0x%08X (block events will be dropped)", hr);
        m_notifyPort = INVALID_HANDLE_VALUE;
        // Non-fatal: policy channel still works; event delivery is degraded.
    }

    LOG_INFO("Connected to kernel driver command port");

    m_connected.store(true);
    m_reconnectAttempts.store(0);

    // Notify connection callback
    {
        std::lock_guard<std::mutex> lock(m_callbackMutex);
        if (m_connectionCallback) {
            m_connectionCallback(true);
        }
    }

    return true;
}

void KernelComm::DisconnectFromDriver() {
    m_connected.store(false);

    if (m_commandPort != INVALID_HANDLE_VALUE) {
        CloseHandle(m_commandPort);
        m_commandPort = INVALID_HANDLE_VALUE;
    }

    if (m_notifyPort != INVALID_HANDLE_VALUE) {
        CloseHandle(m_notifyPort);
        m_notifyPort = INVALID_HANDLE_VALUE;
    }

    // Notify connection callback
    {
        std::lock_guard<std::mutex> lock(m_callbackMutex);
        if (m_connectionCallback) {
            m_connectionCallback(false);
        }
    }
}

// ============================================================================
// MESSAGE SENDING
// ============================================================================

bool KernelComm::SendMessage(void* message, uint32_t size, void* reply, uint32_t replySize) {
    if (!m_connected.load() || m_commandPort == INVALID_HANDLE_VALUE) {
        return false;
    }

    DWORD bytesReturned = 0;
    HRESULT hr = FilterSendMessage(
        m_commandPort,
        message,
        size,
        reply,
        replySize,
        &bytesReturned
    );

    if (FAILED(hr)) {
        LOG_WARNING("FilterSendMessage failed: 0x%08X", hr);

        // Check if driver disconnected
        if (hr == HRESULT_FROM_WIN32(ERROR_INVALID_HANDLE) ||
            hr == HRESULT_FROM_WIN32(ERROR_BROKEN_PIPE)) {
            m_connected.store(false);
        }
        return false;
    }

    return true;
}

// ============================================================================
// POLICY OPERATIONS
// ============================================================================

bool KernelComm::UpdateFilePolicy(
    const std::wstring& filePath,
    uint32_t classification,
    uint32_t blockedActions,
    bool isPermanent
)
{
    // Resolve file path to file ID
    DLP_FILE_ID fileId;
    if (!GetFileId(filePath, fileId)) {
        LOG_WARNING("Failed to resolve file ID for: %ws", filePath.c_str());
        return false;
    }

    // Build policy entry
    DLP_POLICY_ENTRY policy = {0};
    policy.FileId = fileId;
    policy.Classification = classification;
    policy.BlockedActions = blockedActions;
    policy.Flags = DLP_ENTRY_FLAG_VALID;
    if (isPermanent) {
        policy.Flags |= DLP_ENTRY_FLAG_PERMANENT;
    }

    return UpdatePolicy(fileId, policy);
}

bool KernelComm::UpdatePolicy(const DLP_FILE_ID& fileId, const DLP_POLICY_ENTRY& policy) {
    DLP_POLICY_UPDATE_MSG msg = {0};
    DLP_INIT_MESSAGE_HEADER(&msg, DLP_MSG_POLICY_UPDATE);
    msg.Entry = policy;
    msg.Entry.FileId = fileId;

    return SendMessage(&msg, sizeof(msg), nullptr, 0);
}

size_t KernelComm::BulkUpdatePolicies(const std::vector<DLP_POLICY_ENTRY>& policies) {
    size_t updated = 0;

    // Send in batches of DLP_MAX_BULK_ENTRIES
    for (size_t i = 0; i < policies.size(); i += DLP_MAX_BULK_ENTRIES) {
        DLP_POLICY_BULK_UPDATE_MSG msg = {0};
        DLP_INIT_MESSAGE_HEADER(&msg, DLP_MSG_POLICY_BULK_UPDATE);

        size_t batchSize = std::min(
            policies.size() - i,
            static_cast<size_t>(DLP_MAX_BULK_ENTRIES)
        );

        msg.EntryCount = static_cast<uint32_t>(batchSize);

        for (size_t j = 0; j < batchSize; j++) {
            msg.Entries[j] = policies[i + j];
        }

        if (SendMessage(&msg, sizeof(msg), nullptr, 0)) {
            updated += batchSize;
        } else {
            break;
        }
    }

    return updated;
}

bool KernelComm::RemovePolicy(const DLP_FILE_ID& fileId) {
    DLP_POLICY_REMOVE_MSG msg = {0};
    DLP_INIT_MESSAGE_HEADER(&msg, DLP_MSG_POLICY_REMOVE);
    msg.FileId = fileId;

    return SendMessage(&msg, sizeof(msg), nullptr, 0);
}

bool KernelComm::ClearAllPolicies() {
    DLP_MESSAGE_HEADER msg = {0};
    msg.Size = sizeof(msg);
    msg.Type = DLP_MSG_POLICY_CLEAR;

    return SendMessage(&msg, sizeof(msg), nullptr, 0);
}

bool KernelComm::UpdateConfig(
    bool failClosed,
    bool auditMode,
    uint32_t maxCacheEntries,
    uint32_t cacheTTLSeconds
)
{
    DLP_CONFIG_UPDATE_MSG msg = {0};
    DLP_INIT_MESSAGE_HEADER(&msg, DLP_MSG_CONFIG_UPDATE);
    msg.FailClosedMode = failClosed ? 1 : 0;
    msg.AuditMode = auditMode ? 1 : 0;
    msg.MaxCacheEntries = maxCacheEntries;
    msg.CacheEntryTTL = cacheTTLSeconds;

    return SendMessage(&msg, sizeof(msg), nullptr, 0);
}

// ============================================================================
// CALLBACKS
// ============================================================================

void KernelComm::RegisterBlockEventCallback(BlockEventCallback callback) {
    std::lock_guard<std::mutex> lock(m_callbackMutex);
    m_blockEventCallback = std::move(callback);
}

void KernelComm::RegisterConnectionCallback(ConnectionStatusCallback callback) {
    std::lock_guard<std::mutex> lock(m_callbackMutex);
    m_connectionCallback = std::move(callback);
}

// ============================================================================
// NOTIFICATION THREAD
// ============================================================================

void KernelComm::NotificationThread() {
    LOG_INFO("Notification thread started");

    // Buffer for receiving messages
    alignas(16) uint8_t buffer[sizeof(FILTER_MESSAGE_HEADER) + sizeof(DLP_EVENT_NOTIFICATION)];

    while (!m_shutdownRequested.load()) {
        // Reconnect if needed (exponential backoff, never a busy spin). The
        // loop retries indefinitely with the backoff capped so the driver can
        // be loaded at any later time.
        if (!m_connected.load()) {
            if (m_shutdownRequested.load()) {
                break;
            }

            int attempt = m_reconnectAttempts.load();
            // Backoff: 1s, 2s, 4s, 8s, ... capped at RECONNECT_DELAY_MS * 8.
            int delayMs = RECONNECT_DELAY_MS << std::min(attempt, 3);
            LOG_INFO("Attempting to reconnect to driver...");
            std::this_thread::sleep_for(std::chrono::milliseconds(delayMs));

            if (m_shutdownRequested.load()) {
                break;
            }

            if (ConnectToDriver()) {
                LOG_INFO("Reconnected to driver");
                m_reconnectAttempts.store(0);
            } else {
                m_reconnectAttempts++;
            }
            continue;
        }

        // Wait for a message from the kernel on the NOTIFICATION port.
        HRESULT hr = FilterGetMessage(
            m_notifyPort,
            reinterpret_cast<PFILTER_MESSAGE_HEADER>(buffer),
            sizeof(buffer),
            nullptr  // Overlapped (synchronous)
        );

        if (FAILED(hr)) {
            if (m_shutdownRequested.load()) {
                break;
            }

            if (hr == HRESULT_FROM_WIN32(ERROR_OPERATION_ABORTED)) {
                // Shutdown requested
                break;
            }

            if (hr == HRESULT_FROM_WIN32(ERROR_INVALID_HANDLE) ||
                hr == HRESULT_FROM_WIN32(ERROR_BROKEN_PIPE)) {
                LOG_WARNING("Connection to driver lost");
                m_connected.store(false);
            }
            continue;
        }

        if (m_shutdownRequested.load()) {
            break;
        }

        // Process message. The payload arrives after the standard
        // FILTER_MESSAGE_HEADER in the DLP_EVENT_NOTIFICATION wire format.
        PDLP_EVENT_NOTIFICATION event = reinterpret_cast<PDLP_EVENT_NOTIFICATION>(
            buffer + sizeof(FILTER_MESSAGE_HEADER)
        );

        // Dispatch to callback
        {
            std::lock_guard<std::mutex> lock(m_callbackMutex);
            if (m_blockEventCallback) {
                m_blockEventCallback(*event);
            }
        }
    }

    LOG_INFO("Notification thread stopped");
}

// ============================================================================
// FILE ID RESOLUTION
// ============================================================================

bool KernelComm::GetFileId(const std::wstring& filePath, DLP_FILE_ID& fileId) {
    return FileIdResolver::Resolve(filePath, fileId);
}

bool KernelComm::GetVolumeSerialNumber(const std::wstring& volumePath, uint32_t& serialNumber) {
    DWORD volumeSerial = 0;
    DWORD maxComponentLength = 0;
    DWORD fileSystemFlags = 0;

    if (!GetVolumeInformationW(
        volumePath.c_str(),
        nullptr, 0,          // Volume name buffer
        &volumeSerial,
        &maxComponentLength,
        &fileSystemFlags,
        nullptr, 0           // File system name buffer
    )) {
        return false;
    }

    serialNumber = volumeSerial;
    return true;
}

// ============================================================================
// FILE ID RESOLVER
// ============================================================================

bool FileIdResolver::Resolve(const std::wstring& filePath, DLP_FILE_ID& fileId) {
    // Zero out file ID
    memset(&fileId, 0, sizeof(fileId));

    // Open file to get its ID
    HANDLE hFile = CreateFileW(
        filePath.c_str(),
        FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,  // Required for directories
        nullptr
    );

    if (hFile == INVALID_HANDLE_VALUE) {
        LOG_WARNING("Failed to open file for ID resolution: %ws (error: %d)",
            filePath.c_str(), GetLastError());
        return false;
    }

    bool success = false;

    // Get file index (NTFS file reference number)
    BY_HANDLE_FILE_INFORMATION fileInfo;
    if (GetFileInformationByHandle(hFile, &fileInfo)) {
        // Combine high and low parts into 64-bit file ID
        fileId.FileId = (static_cast<uint64_t>(fileInfo.nFileIndexHigh) << 32) |
                        static_cast<uint64_t>(fileInfo.nFileIndexLow);
        fileId.VolumeSerialNumber = fileInfo.dwVolumeSerialNumber;
        success = true;
    }

    CloseHandle(hFile);
    return success;
}

size_t FileIdResolver::ResolveBatch(
    const std::vector<std::wstring>& filePaths,
    std::vector<DLP_FILE_ID>& fileIds
)
{
    fileIds.clear();
    fileIds.reserve(filePaths.size());

    size_t resolved = 0;
    for (const auto& path : filePaths) {
        DLP_FILE_ID id;
        if (Resolve(path, id)) {
            fileIds.push_back(id);
            resolved++;
        } else {
            // Push empty ID to maintain alignment with input
            fileIds.push_back({0, 0});
        }
    }

    return resolved;
}

bool FileIdResolver::GetNtfsFileId(HANDLE fileHandle, uint64_t& fileId) {
    BY_HANDLE_FILE_INFORMATION info;
    if (!GetFileInformationByHandle(fileHandle, &info)) {
        return false;
    }

    fileId = (static_cast<uint64_t>(info.nFileIndexHigh) << 32) |
             static_cast<uint64_t>(info.nFileIndexLow);
    return true;
}

bool FileIdResolver::TrackFileId(const std::wstring& filePath, DLP_FILE_ID& fileId) {
    // For tracking file across renames, we store the file ID
    // and periodically verify it still exists
    return Resolve(filePath, fileId);
}

} // namespace DLP
} // namespace Pritrak
