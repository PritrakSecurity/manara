/**
 * @file ClassificationService.h
 * @brief File classification service with kernel driver integration
 * 
 * PRITRAK Enterprise DLP Agent - Classification Service
 * 
 * Handles file classification and pushes policy to kernel driver.
 * The kernel driver only enforces - this service provides intelligence.
 * 
 * Copyright (C) 2026 Pritrak Security
 */

#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <atomic>
#include <memory>
#include <functional>

#include "../../common/shared/dlp_shared.h"
#include "../comms/KernelComm.h"
#include "DeepContentInspector.h"

namespace Pritrak {
namespace DLP {

/**
 * @struct ClassificationResult
 * @brief Result of file classification
 */
struct ClassificationResult {
    std::wstring filePath;
    DLP_FILE_ID fileId;
    uint32_t classification;        // DLP_CLASSIFICATION flags
    uint32_t confidence;            // 0-100 confidence score
    std::wstring matchedRuleName;
    std::wstring matchedPattern;
    std::vector<std::wstring> matchedKeywords; // Keywords of the matched rule
    bool isProtected;               // Should this file be protected?

    // DSPM contextual risk metadata (Phase 2 DCI)
    std::string exposureLevel;      // PUBLIC, INTERNAL, RESTRICTED
    int riskScore;                  // 0-100 contextual risk score
    std::string contentSnippet;     // Masked, truncated content snippet (never raw PII)
    std::string ownerSid;           // File owner SID (S-1-...-...)
    std::vector<std::string> dciWarnings;  // DCI diagnostics (fixed, non-sensitive strings)
};

/**
 * @struct ClassificationRule
 * @brief Rule for classifying files
 */
struct ClassificationRule {
    std::wstring ruleId;
    std::wstring ruleName;
    uint32_t priority;              // Higher = evaluated first
    bool enabled;

    // Conditions
    std::vector<std::wstring> keywords;         // Content keywords
    std::vector<std::wstring> patterns;         // Regex patterns
    std::vector<std::wstring> fileExtensions;   // File extensions
    std::vector<std::wstring> pathPatterns;     // Path patterns
    std::wstring fingerprint;                   // Document fingerprint

    // Classification result
    uint32_t classification;        // What classification to assign
    uint32_t blockedActions;        // What actions to block

    // Exceptions
    std::vector<std::wstring> exemptUsers;
    std::vector<std::wstring> exemptPaths;
    std::vector<std::wstring> exemptProcesses;
};

/**
 * @class ClassificationService
 * @brief Classifies files and pushes policy to kernel driver
 */
class ClassificationService {
public:
    // Callback types
    using ClassificationCallback = std::function<void(const ClassificationResult&)>;

    /**
     * Get singleton instance
     */
    static ClassificationService& GetInstance();

    /**
     * Initialize the classification service
     * 
     * @param backendUrl - URL of backend server for rule sync
     * @return true if initialized successfully
     */
    bool Initialize(const std::string& backendUrl = "");

    /**
     * Shutdown the service
     */
    void Shutdown();

    /**
     * Classify a file
     * 
     * @param filePath - Path to file to classify
     * @param result - Output classification result
     * 
     * @return true if classified successfully
     */
    bool ClassifyFile(const std::wstring& filePath, ClassificationResult& result);

    /**
     * Classify file and push policy to kernel
     * 
     * @param filePath - Path to file
     * 
     * @return true if classified and pushed successfully
     */
    bool ClassifyAndProtect(const std::wstring& filePath);

    /**
     * Classify content (without file)
     * 
     * @param content - Content to classify
     * @param fileName - Optional file name for extension matching
     * 
     * @return Classification result
     */
    ClassificationResult ClassifyContent(
        const std::string& content,
        const std::wstring& fileName = L""
    );

    /**
     * Add a classification rule
     * 
     * @param rule - Rule to add
     */
    void AddRule(const ClassificationRule& rule);

    /**
     * Remove a classification rule
     * 
     * @param ruleId - ID of rule to remove
     */
    void RemoveRule(const std::wstring& ruleId);

    /**
     * Clear all rules
     */
    void ClearRules();

    /**
     * Load rules from JSON
     * 
     * @param json - JSON string containing rules
     * 
     * @return Number of rules loaded
     */
    size_t LoadRulesFromJson(const std::string& json);

    /**
     * Sync rules from backend
     * 
     * @return true if sync successful
     */
    bool SyncRulesFromBackend();

    /**
     * Register classification callback
     */
    void RegisterCallback(ClassificationCallback callback);

    /**
     * Scan directory for classified files
     * 
     * @param directoryPath - Directory to scan
     * @param recursive - Whether to scan subdirectories
     * 
     * @return Number of protected files found
     */
    size_t ScanDirectory(const std::wstring& directoryPath, bool recursive = true);

    /**
     * Get protected file count
     */
    size_t GetProtectedFileCount() const;

    /**
     * Check if file is protected
     * 
     * @param filePath - Path to file
     * @return true if file has protection policy
     */
    bool IsFileProtected(const std::wstring& filePath) const;

private:
    ClassificationService();
    ~ClassificationService();

    // Non-copyable
    ClassificationService(const ClassificationService&) = delete;
    ClassificationService& operator=(const ClassificationService&) = delete;

    // Internal methods
    bool MatchesRule(
        const ClassificationRule& rule,
        const std::wstring& filePath,
        const std::string& content
    );
    bool MatchKeywords(const std::vector<std::wstring>& keywords, const std::string& content);
    bool MatchPatterns(const std::vector<std::wstring>& patterns, const std::string& content);
    bool MatchExtension(const std::vector<std::wstring>& extensions, const std::wstring& filePath);
    bool MatchPath(const std::vector<std::wstring>& pathPatterns, const std::wstring& filePath);
    std::string ReadFileContent(const std::wstring& filePath, size_t maxBytes = 1048576);
    bool PushPolicyToKernel(const ClassificationResult& result);

    // Phase 2 DSPM Deep Content Inspection (DCI)
    std::string CalculateExposure(const std::wstring& filePath);
    std::string GetFileOwnerSid(const std::wstring& filePath) const;
    int CalculateRiskScore(bool hasPII, const std::string& exposure) const;
    void RunDeepContentInspection(const std::wstring& filePath, ClassificationResult& result);

    // DSPM discovery reporting
    std::string ComputeSha256(const std::wstring& filePath) const;
    std::string ClassificationToString(uint32_t classification) const;
    void SendDiscoveryUpdate(const std::wstring& filePath, const ClassificationResult& result);

    // State
    std::atomic<bool> m_initialized;
    std::string m_backendUrl;

    // Rules
    std::vector<ClassificationRule> m_rules;
    mutable std::mutex m_rulesMutex;

    // Protected files tracking
    std::map<std::wstring, DLP_FILE_ID> m_protectedFiles;
    mutable std::mutex m_filesMutex;

    // Callbacks
    std::vector<ClassificationCallback> m_callbacks;
    std::mutex m_callbacksMutex;

    // Kernel communication
    KernelComm* m_kernelComm;

    // Deep Content Inspector (detection + extraction + RE2 PII scanning).
    DeepContentInspector m_dciInspector;
};

/**
 * @class FileMonitor
 * @brief Monitors file system for new/changed files to classify
 */
class FileMonitor {
public:
    /**
     * Start monitoring a directory
     * 
     * @param directoryPath - Directory to monitor
     * @param recursive - Whether to monitor subdirectories
     * 
     * @return true if monitoring started
     */
    bool StartMonitoring(const std::wstring& directoryPath, bool recursive = true);

    /**
     * Stop all monitoring
     */
    void StopMonitoring();

    /**
     * Add path to monitor
     */
    void AddWatchPath(const std::wstring& path);

    /**
     * Remove path from monitoring
     */
    void RemoveWatchPath(const std::wstring& path);

private:
    struct WatchEntry {
        std::wstring path;
        HANDLE handle;
        OVERLAPPED overlapped;
        alignas(8) uint8_t buffer[65536];
        bool recursive;
    };

    std::vector<std::unique_ptr<WatchEntry>> m_watches;
    std::atomic<bool> m_running;
    std::unique_ptr<std::thread> m_watchThread;
    HANDLE m_completionPort;
};

} // namespace DLP
} // namespace Pritrak
