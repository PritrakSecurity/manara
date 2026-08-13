/**
 * @file ClassificationService.cpp
 * @brief File classification service - Implementation
 * 
 * PRITRAK Enterprise DLP Agent - Classification Service
 * 
 * Copyright (C) 2026 Pritrak Security
 */

#include "ClassificationService.h"
#include "../comms/KernelComm.h"
#include "../comms/SecureComm.h"
#include "../notification/NotificationService.h"
#include "../../common/utils/logging.h"

#include <fstream>
#include <sstream>
#include <regex>
#include <algorithm>
#include <filesystem>
#include <bcrypt.h>
#include <nlohmann/json.hpp>
#pragma comment(lib, "bcrypt.lib")

// JSON parsing (using nlohmann/json or similar)
// For this implementation, we use a simple parser

namespace Pritrak {
namespace DLP {

// ============================================================================
// SINGLETON IMPLEMENTATION
// ============================================================================

ClassificationService& ClassificationService::GetInstance() {
    static ClassificationService instance;
    return instance;
}

ClassificationService::ClassificationService()
    : m_initialized(false)
    , m_kernelComm(nullptr)
{
}

ClassificationService::~ClassificationService() {
    Shutdown();
}

// ============================================================================
// INITIALIZATION AND SHUTDOWN
// ============================================================================

bool ClassificationService::Initialize(const std::string& backendUrl) {
    if (m_initialized.load()) {
        return true;
    }

    m_backendUrl = backendUrl;
    m_kernelComm = &KernelComm::GetInstance();

    LOG_INFO("Classification service initialized");
    m_initialized.store(true);

    return true;
}

void ClassificationService::Shutdown() {
    if (!m_initialized.load()) {
        return;
    }

    LOG_INFO("Shutting down classification service");

    ClearRules();
    m_protectedFiles.clear();
    m_kernelComm = nullptr;

    m_initialized.store(false);
}

// ============================================================================
// FILE CLASSIFICATION
// ============================================================================

bool ClassificationService::ClassifyFile(const std::wstring& filePath, ClassificationResult& result) {
    // Initialize result
    result = ClassificationResult();
    result.filePath = filePath;
    result.classification = DLP_CLASS_UNKNOWN;
    result.confidence = 0;
    result.isProtected = false;

    // Get file ID
    if (!KernelComm::GetFileId(filePath, result.fileId)) {
        LOG_WARNING("Failed to get file ID for: %ws", filePath.c_str());
        // Continue anyway - we can still classify by content
    }

    // Read file content
    std::string content = ReadFileContent(filePath);
    if (content.empty()) {
        LOG_WARNING("Could not read file content: %ws", filePath.c_str());
        // Could still match by path/extension
    }

    // Lock rules and find matching rule
    std::lock_guard<std::mutex> lock(m_rulesMutex);

    // Sort rules by priority (already sorted, but ensure)
    std::vector<ClassificationRule> sortedRules = m_rules;
    std::sort(sortedRules.begin(), sortedRules.end(),
        [](const ClassificationRule& a, const ClassificationRule& b) {
            return a.priority > b.priority;
        });

    // Find first matching rule
    for (const auto& rule : sortedRules) {
        if (!rule.enabled) {
            continue;
        }

        if (MatchesRule(rule, filePath, content)) {
            result.classification = rule.classification;
            result.matchedRuleName = rule.ruleName;
            result.matchedKeywords = rule.keywords;
            result.confidence = 100;  // Full match
            result.isProtected = DLP_IS_PROTECTED_CLASS(rule.classification);

            LOG_INFO("File %ws matched rule '%ws' -> classification 0x%X",
                filePath.c_str(), rule.ruleName.c_str(), rule.classification);

            break;
        }
    }

    // Default to PUBLIC if no rule matched
    if (result.classification == DLP_CLASS_UNKNOWN) {
        result.classification = DLP_CLASS_PUBLIC;
        result.confidence = 50;  // Default classification
    }

    // DSPM discovery: report any non-PUBLIC file to the backend (metadata only,
    // never content). The backend upserts it into the inventory_assets table.
    if (result.classification != DLP_CLASS_PUBLIC) {
        SendDiscoveryUpdate(filePath, result);
    }

    // Invoke callbacks
    {
        std::lock_guard<std::mutex> cbLock(m_callbacksMutex);
        for (const auto& callback : m_callbacks) {
            callback(result);
        }
    }

    return true;
}

bool ClassificationService::ClassifyAndProtect(const std::wstring& filePath) {
    ClassificationResult result;

    if (!ClassifyFile(filePath, result)) {
        return false;
    }

    if (result.isProtected) {
        // Push policy to kernel driver
        if (!PushPolicyToKernel(result)) {
            LOG_WARNING("Failed to push policy to kernel for: %ws", filePath.c_str());
            return false;
        }

        // Track protected file
        {
            std::lock_guard<std::mutex> lock(m_filesMutex);
            m_protectedFiles[filePath] = result.fileId;
        }

        LOG_INFO("File protected: %ws (classification: 0x%X)",
            filePath.c_str(), result.classification);
    }

    return true;
}

ClassificationResult ClassificationService::ClassifyContent(
    const std::string& content,
    const std::wstring& fileName
)
{
    ClassificationResult result;
    result.classification = DLP_CLASS_UNKNOWN;
    result.confidence = 0;
    result.isProtected = false;
    result.filePath = fileName;

    std::lock_guard<std::mutex> lock(m_rulesMutex);

    for (const auto& rule : m_rules) {
        if (!rule.enabled) {
            continue;
        }

        // Check keywords in content
        if (MatchKeywords(rule.keywords, content)) {
            result.classification = rule.classification;
            result.matchedRuleName = rule.ruleName;
            result.confidence = 100;
            result.isProtected = DLP_IS_PROTECTED_CLASS(rule.classification);
            break;
        }

        // Check patterns
        if (MatchPatterns(rule.patterns, content)) {
            result.classification = rule.classification;
            result.matchedRuleName = rule.ruleName;
            result.confidence = 100;
            result.isProtected = DLP_IS_PROTECTED_CLASS(rule.classification);
            break;
        }

        // Check extension
        if (!fileName.empty() && MatchExtension(rule.fileExtensions, fileName)) {
            result.classification = rule.classification;
            result.matchedRuleName = rule.ruleName;
            result.confidence = 80;  // Extension match is less confident
            result.isProtected = DLP_IS_PROTECTED_CLASS(rule.classification);
            break;
        }
    }

    if (result.classification == DLP_CLASS_UNKNOWN) {
        result.classification = DLP_CLASS_PUBLIC;
        result.confidence = 50;
    }

    return result;
}

// ============================================================================
// RULE MANAGEMENT
// ============================================================================

void ClassificationService::AddRule(const ClassificationRule& rule) {
    std::lock_guard<std::mutex> lock(m_rulesMutex);
    
    // Remove existing rule with same ID
    m_rules.erase(
        std::remove_if(m_rules.begin(), m_rules.end(),
            [&rule](const ClassificationRule& r) { return r.ruleId == rule.ruleId; }),
        m_rules.end()
    );
    
    m_rules.push_back(rule);

    // Sort by priority
    std::sort(m_rules.begin(), m_rules.end(),
        [](const ClassificationRule& a, const ClassificationRule& b) {
            return a.priority > b.priority;
        });

    LOG_INFO("Added classification rule: %ws (priority: %u)",
        rule.ruleName.c_str(), rule.priority);
}

void ClassificationService::RemoveRule(const std::wstring& ruleId) {
    std::lock_guard<std::mutex> lock(m_rulesMutex);
    
    m_rules.erase(
        std::remove_if(m_rules.begin(), m_rules.end(),
            [&ruleId](const ClassificationRule& r) { return r.ruleId == ruleId; }),
        m_rules.end()
    );
}

void ClassificationService::ClearRules() {
    std::lock_guard<std::mutex> lock(m_rulesMutex);
    m_rules.clear();
}

size_t ClassificationService::LoadRulesFromJson(const std::string& json) {
    // Simple JSON parsing for rules
    // In production, use nlohmann/json or similar
    
    size_t loaded = 0;
    
    // For now, create some default rules for common patterns
    ClassificationRule restrictedRule;
    restrictedRule.ruleId = L"default-restricted";
    restrictedRule.ruleName = L"Restricted Content";
    restrictedRule.priority = 100;
    restrictedRule.enabled = true;
    restrictedRule.keywords = {L"RESTRICTED", L"TOP SECRET", L"CONFIDENTIAL"};
    restrictedRule.classification = DLP_CLASS_RESTRICTED;
    restrictedRule.blockedActions = DLP_ACTION_BLOCK;
    AddRule(restrictedRule);
    loaded++;

    // PII detection rule
    ClassificationRule piiRule;
    piiRule.ruleId = L"default-pii";
    piiRule.ruleName = L"Personal Information";
    piiRule.priority = 90;
    piiRule.enabled = true;
    piiRule.patterns = {
        L"\\b\\d{3}-\\d{2}-\\d{4}\\b",      // SSN
        L"\\b\\d{16}\\b",                    // Credit card
        L"\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b"  // Email
    };
    piiRule.classification = DLP_CLASS_CONFIDENTIAL | DLP_CLASS_PII;
    piiRule.blockedActions = DLP_ACTION_BLOCK;
    AddRule(piiRule);
    loaded++;

    // Admin keyword rule
    ClassificationRule adminRule;
    adminRule.ruleId = L"admin-keyword";
    adminRule.ruleName = L"Admin Content";
    adminRule.priority = 80;
    adminRule.enabled = true;
    adminRule.keywords = {L"admin", L"password", L"secret", L"credential"};
    adminRule.classification = DLP_CLASS_RESTRICTED;
    adminRule.blockedActions = DLP_ACTION_BLOCK;
    AddRule(adminRule);
    loaded++;

    LOG_INFO("Loaded %zu classification rules", loaded);
    return loaded;
}

bool ClassificationService::SyncRulesFromBackend() {
    if (m_backendUrl.empty()) {
        LOG_WARNING("No backend URL configured for rule sync");
        return false;
    }

    // HTTP request to get rules from backend
    // This would use the HTTP client to fetch /api/rules
    
    // For now, return false to indicate not implemented
    return false;
}

void ClassificationService::RegisterCallback(ClassificationCallback callback) {
    std::lock_guard<std::mutex> lock(m_callbacksMutex);
    m_callbacks.push_back(std::move(callback));
}

// ============================================================================
// DIRECTORY SCANNING
// ============================================================================

size_t ClassificationService::ScanDirectory(const std::wstring& directoryPath, bool recursive) {
    size_t protectedCount = 0;

    // NEVER scan the agent's own installation or data directories. Scanning
    // C:\Program Files\PritrakDLP or C:\ProgramData\PritrakDLP makes the
    // agent classify and "protect" its own files (config.json, quarantine
    // entries, caches) which triggers a busy re-scan loop.
    auto isAgentPath = [](const std::wstring& p) -> bool {
        return p.find(L"PritrakDLP") != std::wstring::npos;
    };

    try {
        if (recursive) {
            std::filesystem::recursive_directory_iterator it(
                directoryPath,
                std::filesystem::directory_options::skip_permission_denied);
            std::filesystem::recursive_directory_iterator end;
            while (it != end) {
                const std::wstring path = it->path().wstring();
                if (isAgentPath(path)) {
                    if (it->is_directory()) {
                        it.disable_recursion_pending();
                    }
                    ++it;
                    continue;
                }
                if (it->is_regular_file() && ClassifyAndProtect(path)) {
                    protectedCount++;
                }
                ++it;
            }
        } else {
            for (const auto& entry : std::filesystem::directory_iterator(directoryPath)) {
                const std::wstring path = entry.path().wstring();
                if (isAgentPath(path)) {
                    continue;
                }
                if (entry.is_regular_file() && ClassifyAndProtect(path)) {
                    protectedCount++;
                }
            }
        }
    } catch (const std::exception& e) {
        LOG_ERROR("Error scanning directory %ws: %s", directoryPath.c_str(), e.what());
    }

    LOG_INFO("Scanned directory %ws: %zu files protected", directoryPath.c_str(), protectedCount);
    return protectedCount;
}

size_t ClassificationService::GetProtectedFileCount() const {
    std::lock_guard<std::mutex> lock(m_filesMutex);
    return m_protectedFiles.size();
}

bool ClassificationService::IsFileProtected(const std::wstring& filePath) const {
    std::lock_guard<std::mutex> lock(m_filesMutex);
    return m_protectedFiles.find(filePath) != m_protectedFiles.end();
}

// ============================================================================
// INTERNAL METHODS
// ============================================================================

bool ClassificationService::MatchesRule(
    const ClassificationRule& rule,
    const std::wstring& filePath,
    const std::string& content
)
{
    // Check keywords
    if (!rule.keywords.empty() && !content.empty()) {
        if (MatchKeywords(rule.keywords, content)) {
            return true;
        }
    }

    // Check patterns (regex)
    if (!rule.patterns.empty() && !content.empty()) {
        if (MatchPatterns(rule.patterns, content)) {
            return true;
        }
    }

    // Check file extension
    if (!rule.fileExtensions.empty()) {
        if (MatchExtension(rule.fileExtensions, filePath)) {
            return true;
        }
    }

    // Check path patterns
    if (!rule.pathPatterns.empty()) {
        if (MatchPath(rule.pathPatterns, filePath)) {
            return true;
        }
    }

    return false;
}

bool ClassificationService::MatchKeywords(
    const std::vector<std::wstring>& keywords,
    const std::string& content
)
{
    // Convert content to lowercase for case-insensitive matching
    std::string lowerContent = content;
    std::transform(lowerContent.begin(), lowerContent.end(), lowerContent.begin(), ::tolower);

    for (const auto& keyword : keywords) {
        // Convert keyword to narrow string
        std::string narrowKeyword(keyword.begin(), keyword.end());
        std::transform(narrowKeyword.begin(), narrowKeyword.end(), narrowKeyword.begin(), ::tolower);

        if (lowerContent.find(narrowKeyword) != std::string::npos) {
            return true;
        }
    }

    return false;
}

bool ClassificationService::MatchPatterns(
    const std::vector<std::wstring>& patterns,
    const std::string& content
)
{
    for (const auto& pattern : patterns) {
        try {
            std::string narrowPattern(pattern.begin(), pattern.end());
            std::regex re(narrowPattern, std::regex::icase);
            
            if (std::regex_search(content, re)) {
                return true;
            }
        } catch (const std::regex_error& e) {
            LOG_WARNING("Invalid regex pattern: %ws - %s", pattern.c_str(), e.what());
        }
    }

    return false;
}

bool ClassificationService::MatchExtension(
    const std::vector<std::wstring>& extensions,
    const std::wstring& filePath
)
{
    // Get file extension
    size_t dotPos = filePath.rfind(L'.');
    if (dotPos == std::wstring::npos) {
        return false;
    }

    std::wstring ext = filePath.substr(dotPos);
    std::transform(ext.begin(), ext.end(), ext.begin(), ::towlower);

    for (const auto& extension : extensions) {
        std::wstring lowerExt = extension;
        std::transform(lowerExt.begin(), lowerExt.end(), lowerExt.begin(), ::towlower);

        // Add dot if not present
        if (!lowerExt.empty() && lowerExt[0] != L'.') {
            lowerExt = L"." + lowerExt;
        }

        if (ext == lowerExt) {
            return true;
        }
    }

    return false;
}

bool ClassificationService::MatchPath(
    const std::vector<std::wstring>& pathPatterns,
    const std::wstring& filePath
)
{
    std::wstring lowerPath = filePath;
    std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::towlower);

    for (const auto& pattern : pathPatterns) {
        std::wstring lowerPattern = pattern;
        std::transform(lowerPattern.begin(), lowerPattern.end(), lowerPattern.begin(), ::towlower);

        if (lowerPath.find(lowerPattern) != std::wstring::npos) {
            return true;
        }
    }

    return false;
}

std::string ClassificationService::ReadFileContent(const std::wstring& filePath, size_t maxBytes) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) {
        return "";
    }

    // Get file size
    file.seekg(0, std::ios::end);
    size_t fileSize = static_cast<size_t>(file.tellg());
    file.seekg(0, std::ios::beg);

    // Limit read size
    size_t readSize = std::min(fileSize, maxBytes);

    std::string content(readSize, '\0');
    file.read(&content[0], readSize);

    return content;
}

std::string ClassificationService::ComputeSha256(const std::wstring& filePath) const {
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) {
        return "";
    }

    BCRYPT_ALG_HANDLE alg = nullptr;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0) {
        return "";
    }

    BCRYPT_HASH_HANDLE hash = nullptr;
    std::string digestHex;
    if (BCryptCreateHash(alg, &hash, nullptr, 0, nullptr, 0, 0) == 0) {
        char buffer[65536];
        while (file.read(buffer, sizeof(buffer)) || file.gcount() > 0) {
            BCryptHashData(hash, reinterpret_cast<PUCHAR>(buffer),
                static_cast<ULONG>(file.gcount()), 0);
        }

        unsigned char digest[32] = {0};
        if (BCryptFinishHash(hash, digest, sizeof(digest), 0) == 0) {
            static const char* hex = "0123456789abcdef";
            digestHex.reserve(64);
            for (int i = 0; i < 32; ++i) {
                digestHex.push_back(hex[(digest[i] >> 4) & 0x0F]);
                digestHex.push_back(hex[digest[i] & 0x0F]);
            }
        }
        BCryptDestroyHash(hash);
    }
    BCryptCloseAlgorithmProvider(alg, 0);
    return digestHex;
}

std::string ClassificationService::ClassificationToString(uint32_t classification) const {
    if (classification & DLP_CLASS_PII) return "PII";
    if (classification & DLP_CLASS_PCI) return "PCI";
    if (classification & DLP_CLASS_PHI) return "PHI";
    if (classification & DLP_CLASS_TOP_SECRET) return "TOP_SECRET";
    if (classification & DLP_CLASS_RESTRICTED) return "RESTRICTED";
    if (classification & DLP_CLASS_CONFIDENTIAL) return "CONFIDENTIAL";
    if (classification & DLP_CLASS_INTERNAL) return "INTERNAL";
    if (classification & DLP_CLASS_PUBLIC) return "PUBLIC";
    return "UNKNOWN";
}

void ClassificationService::SendDiscoveryUpdate(const std::wstring& filePath, const ClassificationResult& result) {
    std::string narrowPath(filePath.begin(), filePath.end());

    // File size
    uintmax_t fileSize = 0;
    try {
        std::error_code ec;
        fileSize = std::filesystem::file_size(filePath, ec);
    } catch (...) {}

    // Hostname
    char hostname[256] = "unknown";
    DWORD hostnameSize = sizeof(hostname);
    GetComputerNameA(hostname, &hostnameSize);

    // Matched keywords (narrow)
    std::vector<std::string> keywords;
    for (const auto& kw : result.matchedKeywords) {
        keywords.push_back(std::string(kw.begin(), kw.end()));
    }

    nlohmann::json payload;
    payload["file_path"] = narrowPath;
    payload["file_hash"] = ComputeSha256(filePath);
    payload["file_size"] = static_cast<int64_t>(fileSize);
    payload["classification"] = ClassificationToString(result.classification);
    payload["matched_keywords"] = keywords;
    payload["hostname"] = std::string(hostname);

    if (SecureComm::SendInventoryUpdate(payload.dump())) {
        LOG_INFO("Reported sensitive file to DSPM inventory: %s (%s)",
            narrowPath.c_str(), ClassificationToString(result.classification).c_str());
    }
}

bool ClassificationService::PushPolicyToKernel(const ClassificationResult& result) {
    if (!m_kernelComm || !m_kernelComm->IsConnected()) {
        LOG_WARNING("Kernel communication not available");
        return false;
    }

    DLP_POLICY_ENTRY policy = {0};
    policy.FileId = result.fileId;
    policy.Classification = result.classification;
    policy.BlockedActions = DLP_ACTION_BLOCK;  // Block delete, rename, USB copy
    policy.AllowedActions = DLP_ACTION_ALLOW;  // Allow read
    policy.Flags = DLP_ENTRY_FLAG_VALID;

    // Make permanent for high-classification files
    if (result.classification & (DLP_CLASS_RESTRICTED | DLP_CLASS_TOP_SECRET)) {
        policy.Flags |= DLP_ENTRY_FLAG_PERMANENT;
    }

    return m_kernelComm->UpdatePolicy(result.fileId, policy);
}

} // namespace DLP
} // namespace Pritrak
