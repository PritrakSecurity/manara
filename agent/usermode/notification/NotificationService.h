/**
 * @file NotificationService.h
 * @brief User notification service for DLP events
 * 
 * PRITRAK Enterprise DLP Agent - Notification Service
 * 
 * Handles displaying user notifications when DLP policy blocks
 * an operation. Provides clear, non-technical explanations.
 * 
 * Copyright (C) 2026 Pritrak Security
 */

#pragma once

#include <windows.h>
#include <shellapi.h>
#include <string>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <atomic>
#include <memory>

#include "../../common/shared/dlp_shared.h"

namespace Pritrak {
namespace DLP {

/**
 * @struct NotificationInfo
 * @brief Information for a single notification
 */
struct NotificationInfo {
    std::wstring title;
    std::wstring message;
    std::wstring filePath;
    std::wstring policyName;
    DLP_OPERATION_TYPE operation;
    DLP_CLASSIFICATION classification;
    DLP_ACTION action;
    uint64_t timestamp;
};

/**
 * @class NotificationService
 * @brief Displays DLP block notifications to users
 * 
 * Uses Windows toast notifications and system tray for
 * displaying DLP policy violations to end users.
 */
class NotificationService {
public:
    /**
     * Get singleton instance
     */
    static NotificationService& GetInstance();

    /**
     * Initialize the notification service
     * 
     * @param appName - Application name for notifications
     * @return true if initialized successfully
     */
    bool Initialize(const std::wstring& appName = L"PRITRAK DLP");

    /**
     * Shutdown the notification service
     */
    void Shutdown();

    /**
     * Queue a notification for display
     * 
     * @param info - Notification information
     */
    void QueueNotification(const NotificationInfo& info);

    /**
     * Show immediate blocking notification
     * 
     * @param operation - Type of blocked operation
     * @param filePath - Path to the file
     * @param classification - File classification
     * @param policyName - Name of blocking policy
     */
    void ShowBlockNotification(
        DLP_OPERATION_TYPE operation,
        const std::wstring& filePath,
        DLP_CLASSIFICATION classification,
        const std::wstring& policyName = L""
    );

    /**
     * Show notification from kernel event
     * 
     * @param event - Event from kernel driver
     */
    void ShowNotificationFromEvent(const DLP_EVENT_NOTIFICATION& event);

    /**
     * Enable/disable notifications
     */
    void SetEnabled(bool enabled);

    /**
     * Check if notifications are enabled
     */
    bool IsEnabled() const;

    /**
     * Set notification timeout in seconds (0 = no timeout)
     */
    void SetTimeout(uint32_t seconds);

private:
    NotificationService();
    ~NotificationService();

    // Non-copyable
    NotificationService(const NotificationService&) = delete;
    NotificationService& operator=(const NotificationService&) = delete;

    // Internal methods
    void NotificationThread();
    void ProcessNotification(const NotificationInfo& info);
    std::wstring GetOperationName(DLP_OPERATION_TYPE operation);
    std::wstring GetClassificationName(DLP_CLASSIFICATION classification);
    std::wstring FormatMessage(const NotificationInfo& info);
    void ShowToastNotification(const NotificationInfo& info);
    void ShowMessageBox(const NotificationInfo& info);
    bool CreateSystemTrayIcon();
    void RemoveSystemTrayIcon();

    // State
    std::atomic<bool> m_initialized;
    std::atomic<bool> m_enabled;
    std::atomic<bool> m_shutdownRequested;
    std::wstring m_appName;
    uint32_t m_timeoutSeconds;

    // Notification queue
    std::queue<NotificationInfo> m_notificationQueue;
    std::mutex m_queueMutex;
    std::condition_variable m_queueCondition;

    // Worker thread
    std::unique_ptr<std::thread> m_workerThread;

    // System tray
    NOTIFYICONDATAW m_trayIcon;
    HWND m_hiddenWindow;
    bool m_trayIconCreated;

    // Toast notification support
    bool m_toastSupported;
};

/**
 * @class NotificationBuilder
 * @brief Fluent builder for creating notifications
 */
class NotificationBuilder {
public:
    NotificationBuilder& SetTitle(const std::wstring& title);
    NotificationBuilder& SetMessage(const std::wstring& message);
    NotificationBuilder& SetFilePath(const std::wstring& path);
    NotificationBuilder& SetPolicy(const std::wstring& policyName);
    NotificationBuilder& SetOperation(DLP_OPERATION_TYPE op);
    NotificationBuilder& SetClassification(DLP_CLASSIFICATION cls);
    NotificationBuilder& SetAction(DLP_ACTION action);

    NotificationInfo Build() const;
    void Show() const;

private:
    NotificationInfo m_info;
};

} // namespace DLP
} // namespace Pritrak
