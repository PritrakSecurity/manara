/**
 * @file NotificationService.cpp
 * @brief User notification service - Implementation
 * 
 * PRITRAK Enterprise DLP Agent - Notification Service
 * 
 * Provides clear, user-friendly notifications when DLP policy
 * blocks operations. Uses modern Windows notification APIs.
 * 
 * Copyright (C) 2026 Pritrak Security
 */

#include "NotificationService.h"
#include <shellapi.h>
#include <commctrl.h>
#include <sstream>
#include <iomanip>
#include <chrono>

// For logging
#include "../../common/utils/logging.h"

#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "comctl32.lib")

namespace Pritrak {
namespace DLP {

// Window class name for hidden window
static const wchar_t* HIDDEN_WINDOW_CLASS = L"PritrakDLPNotifyWindow";
static const UINT WM_TRAYICON = WM_USER + 1;

// Window procedure for hidden window
static LRESULT CALLBACK HiddenWindowProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_TRAYICON:
            // Handle tray icon events
            if (lParam == WM_LBUTTONDBLCLK) {
                // Double-click on tray icon - could show settings
            }
            return 0;

        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
    }
    return DefWindowProcW(hwnd, msg, wParam, lParam);
}

// ============================================================================
// SINGLETON IMPLEMENTATION
// ============================================================================

NotificationService& NotificationService::GetInstance() {
    static NotificationService instance;
    return instance;
}

NotificationService::NotificationService()
    : m_initialized(false)
    , m_enabled(true)
    , m_shutdownRequested(false)
    , m_appName(L"PRITRAK DLP")
    , m_timeoutSeconds(10)
    , m_hiddenWindow(nullptr)
    , m_trayIconCreated(false)
    , m_toastSupported(false)
{
    ZeroMemory(&m_trayIcon, sizeof(m_trayIcon));
}

NotificationService::~NotificationService() {
    Shutdown();
}

// ============================================================================
// INITIALIZATION AND SHUTDOWN
// ============================================================================

bool NotificationService::Initialize(const std::wstring& appName) {
    if (m_initialized.load()) {
        return true;
    }

    m_appName = appName;
    LOG_INFO("Initializing notification service: %ws", appName.c_str());

    // Check for toast notification support (Windows 8+)
    OSVERSIONINFOEXW osvi = {sizeof(osvi)};
    m_toastSupported = (osvi.dwMajorVersion >= 10) || 
                       (osvi.dwMajorVersion == 6 && osvi.dwMinorVersion >= 2);

    // Create hidden window for system tray
    WNDCLASSEXW wc = {0};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = HiddenWindowProc;
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.lpszClassName = HIDDEN_WINDOW_CLASS;

    RegisterClassExW(&wc);

    m_hiddenWindow = CreateWindowExW(
        0,
        HIDDEN_WINDOW_CLASS,
        L"",
        WS_POPUP,
        0, 0, 0, 0,
        nullptr,
        nullptr,
        GetModuleHandleW(nullptr),
        nullptr
    );

    if (m_hiddenWindow == nullptr) {
        LOG_WARNING("Failed to create hidden window for notifications");
    }

    // Create system tray icon
    CreateSystemTrayIcon();

    // Start worker thread
    m_shutdownRequested.store(false);
    m_workerThread = std::make_unique<std::thread>(&NotificationService::NotificationThread, this);

    m_initialized.store(true);
    LOG_INFO("Notification service initialized");
    return true;
}

void NotificationService::Shutdown() {
    if (!m_initialized.load()) {
        return;
    }

    LOG_INFO("Shutting down notification service");

    // Signal shutdown
    m_shutdownRequested.store(true);
    m_queueCondition.notify_all();

    // Wait for worker thread
    if (m_workerThread && m_workerThread->joinable()) {
        m_workerThread->join();
        m_workerThread.reset();
    }

    // Remove system tray icon
    RemoveSystemTrayIcon();

    // Destroy hidden window
    if (m_hiddenWindow) {
        DestroyWindow(m_hiddenWindow);
        m_hiddenWindow = nullptr;
    }

    UnregisterClassW(HIDDEN_WINDOW_CLASS, GetModuleHandleW(nullptr));

    m_initialized.store(false);
    LOG_INFO("Notification service shutdown complete");
}

// ============================================================================
// SYSTEM TRAY
// ============================================================================

bool NotificationService::CreateSystemTrayIcon() {
    if (m_hiddenWindow == nullptr) {
        return false;
    }

    m_trayIcon.cbSize = sizeof(m_trayIcon);
    m_trayIcon.hWnd = m_hiddenWindow;
    m_trayIcon.uID = 1;
    m_trayIcon.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    m_trayIcon.uCallbackMessage = WM_TRAYICON;
    m_trayIcon.hIcon = LoadIconW(nullptr, IDI_SHIELD);
    
    wcscpy_s(m_trayIcon.szTip, L"PRITRAK DLP - Protecting your data");

    if (Shell_NotifyIconW(NIM_ADD, &m_trayIcon)) {
        m_trayIconCreated = true;
        return true;
    }

    LOG_WARNING("Failed to create system tray icon");
    return false;
}

void NotificationService::RemoveSystemTrayIcon() {
    if (m_trayIconCreated) {
        Shell_NotifyIconW(NIM_DELETE, &m_trayIcon);
        m_trayIconCreated = false;
    }
}

// ============================================================================
// NOTIFICATION QUEUE
// ============================================================================

void NotificationService::QueueNotification(const NotificationInfo& info) {
    if (!m_enabled.load()) {
        return;
    }

    {
        std::lock_guard<std::mutex> lock(m_queueMutex);
        m_notificationQueue.push(info);
    }

    m_queueCondition.notify_one();
}

void NotificationService::NotificationThread() {
    LOG_INFO("Notification worker thread started");

    while (!m_shutdownRequested.load()) {
        NotificationInfo info;
        bool hasNotification = false;

        {
            std::unique_lock<std::mutex> lock(m_queueMutex);

            m_queueCondition.wait(lock, [this] {
                return !m_notificationQueue.empty() || m_shutdownRequested.load();
            });

            if (m_shutdownRequested.load()) {
                break;
            }

            if (!m_notificationQueue.empty()) {
                info = m_notificationQueue.front();
                m_notificationQueue.pop();
                hasNotification = true;
            }
        }

        if (hasNotification) {
            ProcessNotification(info);
        }
    }

    LOG_INFO("Notification worker thread stopped");
}

void NotificationService::ProcessNotification(const NotificationInfo& info) {
    if (m_toastSupported) {
        ShowToastNotification(info);
    } else {
        ShowMessageBox(info);
    }
}

// ============================================================================
// SHOW NOTIFICATIONS
// ============================================================================

void NotificationService::ShowBlockNotification(
    DLP_OPERATION_TYPE operation,
    const std::wstring& filePath,
    DLP_CLASSIFICATION classification,
    const std::wstring& policyName
)
{
    NotificationInfo info;
    info.title = L"DLP Policy Violation";
    info.filePath = filePath;
    info.policyName = policyName;
    info.operation = operation;
    info.classification = static_cast<DLP_CLASSIFICATION>(classification);
    info.action = DLP_ACTION_BLOCK;
    info.timestamp = GetTickCount64();

    info.message = FormatMessage(info);

    QueueNotification(info);
}

void NotificationService::ShowNotificationFromEvent(const DLP_EVENT_NOTIFICATION& event) {
    NotificationInfo info;
    info.title = L"DLP Security Alert";
    info.filePath = event.FilePath;
    info.operation = static_cast<DLP_OPERATION_TYPE>(event.Operation);
    info.classification = static_cast<DLP_CLASSIFICATION>(event.Classification);
    info.action = static_cast<DLP_ACTION>(event.ActionTaken);
    info.timestamp = event.Header.Timestamp;

    info.message = FormatMessage(info);

    QueueNotification(info);
}

void NotificationService::ShowToastNotification(const NotificationInfo& info) {
    // Use balloon notification via system tray (works on all Windows versions)
    if (!m_trayIconCreated) {
        ShowMessageBox(info);
        return;
    }

    NOTIFYICONDATAW balloon = m_trayIcon;
    balloon.uFlags = NIF_INFO;
    balloon.dwInfoFlags = NIIF_WARNING;
    
    wcscpy_s(balloon.szInfoTitle, info.title.c_str());
    
    // Truncate message if too long
    std::wstring msg = info.message;
    if (msg.length() > 255) {
        msg = msg.substr(0, 252) + L"...";
    }
    wcscpy_s(balloon.szInfo, msg.c_str());

    Shell_NotifyIconW(NIM_MODIFY, &balloon);

    LOG_INFO("Displayed balloon notification: %ws", info.title.c_str());
}

void NotificationService::ShowMessageBox(const NotificationInfo& info) {
    // Format a clear, user-friendly message
    std::wstring fullMessage = FormatMessage(info);

    // Use MessageBoxW on a separate thread to avoid blocking
    std::thread([info, fullMessage]() {
        MessageBoxW(
            nullptr,
            fullMessage.c_str(),
            info.title.c_str(),
            MB_OK | MB_ICONWARNING | MB_SYSTEMMODAL | MB_TOPMOST
        );
    }).detach();

    LOG_INFO("Displayed message box: %ws", info.title.c_str());
}

// ============================================================================
// MESSAGE FORMATTING
// ============================================================================

std::wstring NotificationService::FormatMessage(const NotificationInfo& info) {
    std::wstringstream ss;

    // Operation-specific message
    switch (info.operation) {
        case DLP_OP_FILE_DELETE:
            ss << L"⛔ FILE DELETION BLOCKED\n\n";
            ss << L"You attempted to delete a protected file.\n\n";
            break;

        case DLP_OP_FILE_RENAME:
        case DLP_OP_FILE_MOVE:
            ss << L"⛔ FILE MOVE/RENAME BLOCKED\n\n";
            ss << L"You attempted to move or rename a protected file.\n\n";
            break;

        case DLP_OP_USB_WRITE:
            ss << L"⛔ USB TRANSFER BLOCKED\n\n";
            ss << L"You attempted to copy protected data to a USB device.\n\n";
            break;

        case DLP_OP_FILE_COPY:
            ss << L"⛔ FILE COPY BLOCKED\n\n";
            ss << L"You attempted to copy a protected file to an unauthorized location.\n\n";
            break;

        default:
            ss << L"⛔ OPERATION BLOCKED\n\n";
            ss << L"A data protection policy prevented this operation.\n\n";
            break;
    }

    // File path
    ss << L"File: " << info.filePath << L"\n\n";

    // Classification
    ss << L"Classification: " << GetClassificationName(info.classification) << L"\n\n";

    // Policy name if available
    if (!info.policyName.empty()) {
        ss << L"Policy: " << info.policyName << L"\n\n";
    }

    // Action explanation
    ss << L"This action has been blocked to protect sensitive data.\n";
    ss << L"If you need to perform this operation, please contact your IT administrator.";

    return ss.str();
}

std::wstring NotificationService::GetOperationName(DLP_OPERATION_TYPE operation) {
    switch (operation) {
        case DLP_OP_FILE_DELETE:     return L"Delete";
        case DLP_OP_FILE_RENAME:     return L"Rename";
        case DLP_OP_FILE_MOVE:       return L"Move";
        case DLP_OP_FILE_COPY:       return L"Copy";
        case DLP_OP_USB_WRITE:       return L"USB Transfer";
        case DLP_OP_FILE_WRITE:      return L"Write";
        case DLP_OP_NETWORK_WRITE:   return L"Network Transfer";
        case DLP_OP_CLOUD_UPLOAD:    return L"Cloud Upload";
        case DLP_OP_PRINT:           return L"Print";
        default:                     return L"Unknown";
    }
}

std::wstring NotificationService::GetClassificationName(DLP_CLASSIFICATION classification) {
    std::wstring result;

    if (classification & DLP_CLASS_TOP_SECRET) {
        result += L"TOP SECRET";
    } else if (classification & DLP_CLASS_RESTRICTED) {
        result += L"RESTRICTED";
    } else if (classification & DLP_CLASS_CONFIDENTIAL) {
        result += L"CONFIDENTIAL";
    } else if (classification & DLP_CLASS_INTERNAL) {
        result += L"INTERNAL";
    } else if (classification & DLP_CLASS_PUBLIC) {
        result += L"PUBLIC";
    }

    // Add special flags
    if (classification & DLP_CLASS_PII) {
        if (!result.empty()) result += L" | ";
        result += L"Contains PII";
    }
    if (classification & DLP_CLASS_PCI) {
        if (!result.empty()) result += L" | ";
        result += L"Contains Payment Card Data";
    }
    if (classification & DLP_CLASS_PHI) {
        if (!result.empty()) result += L" | ";
        result += L"Contains Health Information";
    }

    return result.empty() ? L"Unknown" : result;
}

// ============================================================================
// SETTINGS
// ============================================================================

void NotificationService::SetEnabled(bool enabled) {
    m_enabled.store(enabled);
}

bool NotificationService::IsEnabled() const {
    return m_enabled.load();
}

void NotificationService::SetTimeout(uint32_t seconds) {
    m_timeoutSeconds = seconds;
}

// ============================================================================
// NOTIFICATION BUILDER
// ============================================================================

NotificationBuilder& NotificationBuilder::SetTitle(const std::wstring& title) {
    m_info.title = title;
    return *this;
}

NotificationBuilder& NotificationBuilder::SetMessage(const std::wstring& message) {
    m_info.message = message;
    return *this;
}

NotificationBuilder& NotificationBuilder::SetFilePath(const std::wstring& path) {
    m_info.filePath = path;
    return *this;
}

NotificationBuilder& NotificationBuilder::SetPolicy(const std::wstring& policyName) {
    m_info.policyName = policyName;
    return *this;
}

NotificationBuilder& NotificationBuilder::SetOperation(DLP_OPERATION_TYPE op) {
    m_info.operation = op;
    return *this;
}

NotificationBuilder& NotificationBuilder::SetClassification(DLP_CLASSIFICATION cls) {
    m_info.classification = cls;
    return *this;
}

NotificationBuilder& NotificationBuilder::SetAction(DLP_ACTION action) {
    m_info.action = action;
    return *this;
}

NotificationInfo NotificationBuilder::Build() const {
    NotificationInfo result = m_info;
    result.timestamp = GetTickCount64();
    return result;
}

void NotificationBuilder::Show() const {
    NotificationService::GetInstance().QueueNotification(Build());
}

} // namespace DLP
} // namespace Pritrak
