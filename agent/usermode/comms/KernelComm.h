/**
 * @file KernelComm.h
 * @brief User-mode communication with DLP kernel driver
 * 
 * PRITRAK Enterprise DLP Agent - Kernel Communication Layer
 * 
 * This component handles all communication between the user-mode
 * DLP service and the kernel minifilter driver. It provides:
 * - Policy updates to kernel cache
 * - Event notifications from kernel
 * - Driver configuration
 * 
 * Copyright (C) 2026 Pritrak Security
 */

#pragma once

#include <windows.h>
#include <fltUser.h>
#include <string>
#include <vector>
#include <functional>
#include <memory>
#include <atomic>
#include <thread>
#include <mutex>

// Include shared definitions with kernel
#include "../../common/shared/dlp_shared.h"

namespace Pritrak {
namespace DLP {

/**
 * @class KernelComm
 * @brief Manages communication with the DLP kernel minifilter driver
 * 
 * Thread-safe singleton that handles bidirectional communication
 * between user-mode service and kernel driver.
 */
class KernelComm {
public:
    // Callback types
    using BlockEventCallback = std::function<void(const DLP_EVENT_NOTIFICATION&)>;
    using ConnectionStatusCallback = std::function<void(bool connected)>;

    /**
     * Get singleton instance
     */
    static KernelComm& GetInstance();

    /**
     * Initialize communication with kernel driver
     * 
     * @return true if connection established, false otherwise
     */
    bool Initialize();

    /**
     * Shutdown communication
     */
    void Shutdown();

    /**
     * Check if connected to kernel driver
     */
    bool IsConnected() const;

    /**
     * Update policy for a single file
     * 
     * @param filePath - Path to the file
     * @param classification - Classification flags
     * @param blockedActions - Actions to block
     * @param isPermanent - Whether entry should never expire
     * 
     * @return true if update sent successfully
     */
    bool UpdateFilePolicy(
        const std::wstring& filePath,
        uint32_t classification,
        uint32_t blockedActions,
        bool isPermanent = false
    );

    /**
     * Update policy using file ID
     * 
     * @param fileId - File identifier
     * @param policy - Policy entry
     * 
     * @return true if update sent successfully
     */
    bool UpdatePolicy(const DLP_FILE_ID& fileId, const DLP_POLICY_ENTRY& policy);

    /**
     * Bulk update multiple policies
     * 
     * @param policies - Vector of policy entries
     * 
     * @return Number of entries successfully updated
     */
    size_t BulkUpdatePolicies(const std::vector<DLP_POLICY_ENTRY>& policies);

    /**
     * Remove policy for a file
     * 
     * @param fileId - File identifier to remove
     * 
     * @return true if removal sent successfully
     */
    bool RemovePolicy(const DLP_FILE_ID& fileId);

    /**
     * Clear all policies from kernel cache
     * 
     * @return true if command sent successfully
     */
    bool ClearAllPolicies();

    /**
     * Update driver configuration
     * 
     * @param failClosed - Block if no policy found
     * @param auditMode - Log only, don't enforce
     * @param maxCacheEntries - Maximum cache size
     * @param cacheTTLSeconds - Default entry TTL
     * 
     * @return true if config update sent successfully
     */
    bool UpdateConfig(
        bool failClosed,
        bool auditMode,
        uint32_t maxCacheEntries = 0,
        uint32_t cacheTTLSeconds = 0
    );

    /**
     * Get driver statistics
     * 
     * @param stats - Output statistics structure
     * 
     * @return true if stats retrieved successfully
     */
    bool GetStatistics(DLP_STATISTICS& stats);

    /**
     * Register callback for block events
     */
    void RegisterBlockEventCallback(BlockEventCallback callback);

    /**
     * Register callback for connection status changes
     */
    void RegisterConnectionCallback(ConnectionStatusCallback callback);

    /**
     * Get file ID from file path
     * 
     * @param filePath - Path to the file
     * @param fileId - Output file ID
     * 
     * @return true if file ID retrieved successfully
     */
    static bool GetFileId(const std::wstring& filePath, DLP_FILE_ID& fileId);

    /**
     * Get volume serial number
     * 
     * @param volumePath - Path to volume (e.g., L"C:\\")
     * @param serialNumber - Output serial number
     * 
     * @return true if serial number retrieved
     */
    static bool GetVolumeSerialNumber(const std::wstring& volumePath, uint32_t& serialNumber);

private:
    KernelComm();
    ~KernelComm();

    // Non-copyable
    KernelComm(const KernelComm&) = delete;
    KernelComm& operator=(const KernelComm&) = delete;

    // Internal methods
    bool ConnectToDriver();
    void DisconnectFromDriver();
    void NotificationThread();
    bool SendMessage(void* message, uint32_t size, void* reply, uint32_t replySize);

    // State
    HANDLE m_commandPort;
    HANDLE m_notifyPort;
    std::atomic<bool> m_connected;
    std::atomic<bool> m_shutdownRequested;

    // Notification thread
    std::unique_ptr<std::thread> m_notifyThread;

    // Callbacks
    BlockEventCallback m_blockEventCallback;
    ConnectionStatusCallback m_connectionCallback;
    std::mutex m_callbackMutex;

    // Reconnection
    std::atomic<int> m_reconnectAttempts;
    static constexpr int MAX_RECONNECT_ATTEMPTS = 10;
    static constexpr int RECONNECT_DELAY_MS = 1000;
};

/**
 * @class FileIdResolver
 * @brief Helper class to resolve file paths to stable file IDs
 */
class FileIdResolver {
public:
    /**
     * Resolve file path to file ID
     * 
     * @param filePath - Full path to file
     * @param fileId - Output file ID
     * 
     * @return true if resolved successfully
     */
    static bool Resolve(const std::wstring& filePath, DLP_FILE_ID& fileId);

    /**
     * Resolve multiple paths efficiently
     * 
     * @param filePaths - Vector of file paths
     * @param fileIds - Output vector of file IDs
     * 
     * @return Number of successfully resolved paths
     */
    static size_t ResolveBatch(
        const std::vector<std::wstring>& filePaths,
        std::vector<DLP_FILE_ID>& fileIds
    );

    /**
     * Watch file for rename/move and update file ID
     */
    static bool TrackFileId(const std::wstring& filePath, DLP_FILE_ID& fileId);

private:
    static bool GetNtfsFileId(HANDLE fileHandle, uint64_t& fileId);
};

} // namespace DLP
} // namespace Pritrak
