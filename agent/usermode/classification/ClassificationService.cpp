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
#include <sddl.h>
#include <aclapi.h>
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "advapi32.lib")

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

    // Phase 2 DCI: deep content inspection on plain-text files. Computes
    // exposure level, PII findings, risk score, masked content snippet and
    // the file owner SID. Runs inline in the background classification
    // thread (see DLPAgent::StartClassificationScan) - never on the main
    // agent thread.
    RunDeepContentInspection(filePath, result);

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

// ============================================================================
// PHASE 2 DEEP CONTENT INSPECTION (DCI)
// ============================================================================

// Text extensions eligible for DCI. All other files are skipped.
static const std::vector<std::wstring> kDciTextExtensions = {
    L".txt", L".csv", L".json", L".xml", L".log", L".ini"
};

// Performance guardrails: files larger than 10MB are never inspected, and the
// first 1KB is probed for null bytes to reject binary files early.
static const size_t kDciMaxFileBytes = 10 * 1024 * 1024;
static const size_t kDciNullProbeBytes = 1024;
static const size_t kDciSnippetMaxChars = 50;

std::string ClassificationService::ExtractTextFromFile(const std::wstring& filePath) {
    // Only process supported text extensions (case-insensitive).
    size_t dotPos = filePath.rfind(L'.');
    if (dotPos == std::wstring::npos) {
        return "";
    }
    std::wstring ext = filePath.substr(dotPos);
    std::transform(ext.begin(), ext.end(), ext.begin(), ::towlower);

    bool supported = false;
    for (const auto& candidate : kDciTextExtensions) {
        if (ext == candidate) {
            supported = true;
            break;
        }
    }
    if (!supported) {
        return "";
    }

    // Skip files larger than 10MB.
    std::error_code ec;
    uintmax_t fileSize = 0;
    fileSize = std::filesystem::file_size(filePath, ec);
    if (ec || fileSize > kDciMaxFileBytes) {
        return "";
    }

    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) {
        return "";
    }

    // Probe the first 1KB for null bytes; if present, treat as binary and skip.
    std::string probe(kDciNullProbeBytes, '\0');
    file.read(&probe[0], static_cast<std::streamsize>(kDciNullProbeBytes));
    std::streamsize probeRead = file.gcount();
    for (std::streamsize i = 0; i < probeRead; ++i) {
        if (probe[static_cast<size_t>(i)] == '\0') {
            return "";
        }
    }

    // Read the full (bounded) file content. The file is guaranteed to be
    // <= 10MB and text-like, so loading it into a string is safe.
    file.clear();
    file.seekg(0, std::ios::beg);

    std::string content;
    content.reserve(static_cast<size_t>(fileSize));
    char buffer[65536];
    while (file.read(buffer, sizeof(buffer)) || file.gcount() > 0) {
        content.append(buffer, static_cast<size_t>(file.gcount()));
    }

    // Convert raw bytes to UTF-8. ASCII-compatible input is already valid;
    // strip a UTF-8 BOM if present so the snippet is clean.
    if (content.size() >= 3 &&
        static_cast<unsigned char>(content[0]) == 0xEF &&
        static_cast<unsigned char>(content[1]) == 0xBB &&
        static_cast<unsigned char>(content[2]) == 0xBF) {
        content.erase(0, 3);
    }

    return content;
}

bool ClassificationService::IsValidLuhn(const std::string& digits) const {
    if (digits.empty()) {
        return false;
    }
    int sum = 0;
    bool doubleDigit = false;
    for (int i = static_cast<int>(digits.size()) - 1; i >= 0; --i) {
        int n = digits[static_cast<size_t>(i)] - '0';
        if (n < 0 || n > 9) {
            return false;
        }
        if (doubleDigit) {
            n *= 2;
            if (n > 9) {
                n -= 9;
            }
        }
        sum += n;
        doubleDigit = !doubleDigit;
    }
    return (sum % 10) == 0;
}

std::vector<std::string> ClassificationService::ScanTextForPII(const std::string& text) {
    std::vector<std::string> matches;

    // Credit cards: 13-16 digits with optional separators. Luhn-checked to
    // avoid false positives.
    static const std::regex ccRegex(R"(\b(?:\d[ -]*?){13,16}\b)");
    for (std::sregex_iterator it(text.begin(), text.end(), ccRegex), end;
         it != end; ++it) {
        std::string candidate = it->str();
        std::string digits;
        for (char c : candidate) {
            if (c >= '0' && c <= '9') {
                digits.push_back(c);
            }
        }
        if (IsValidLuhn(digits)) {
            matches.push_back(candidate);
        }
    }

    // SSNs: XXX-XX-XXXX
    static const std::regex ssnRegex(R"(\b\d{3}-\d{2}-\d{4}\b)");
    for (std::sregex_iterator it(text.begin(), text.end(), ssnRegex), end;
         it != end; ++it) {
        matches.push_back(it->str());
    }

    // API keys: AWS access keys, GitHub personal access tokens, OpenAI keys.
    static const std::regex apiKeyRegex(
        R"(\b(AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{36}|sk-[a-zA-Z0-9]{48})\b)");
    for (std::sregex_iterator it(text.begin(), text.end(), apiKeyRegex), end;
         it != end; ++it) {
        matches.push_back(it->str());
    }

    return matches;
}

std::string ClassificationService::MaskSensitiveData(const std::string& text) const {
    std::string masked = text;

    // SSN: 123-45-6789 -> ***-**-6789 (keep only the last four digits)
    static const std::regex ssnRegex(R"(\b(\d{3})-(\d{2})-(\d{4})\b)");
    masked = std::regex_replace(masked, ssnRegex, "***-**-$3");

    // Credit cards: keep last four digits only.
    static const std::regex ccRegex(R"(\b(?:\d[ -]*?){13,16}\b)");
    std::string result;
    size_t lastPos = 0;
    for (std::sregex_iterator it(masked.begin(), masked.end(), ccRegex), end;
         it != end; ++it) {
        result.append(masked, lastPos, it->position() - lastPos);
        std::string card = it->str();
        std::string digits;
        for (char c : card) {
            if (c >= '0' && c <= '9') {
                digits.push_back(c);
            }
        }
        result += "****";
        if (digits.size() >= 4) {
            result += digits.substr(digits.size() - 4);
        }
        lastPos = it->position() + card.size();
    }
    if (lastPos == 0) {
        result = masked;
    } else {
        result.append(masked, lastPos, std::string::npos);
    }

    // API keys: keep nothing sensitive, replace with a marker.
    static const std::regex apiKeyRegex(
        R"(\b(AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{36}|sk-[a-zA-Z0-9]{48})\b)");
    result = std::regex_replace(result, apiKeyRegex, "***REDACTED***");

    return result;
}

std::string ClassificationService::CalculateExposure(const std::wstring& filePath) {
    std::wstring lowerPath = filePath;
    std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::towlower);

    if (lowerPath.find(L"public") != std::wstring::npos ||
        lowerPath.find(L"downloads") != std::wstring::npos ||
        lowerPath.find(L"desktop") != std::wstring::npos ||
        lowerPath.find(L"temp") != std::wstring::npos) {
        return "PUBLIC";
    }
    if (lowerPath.find(L"documents") != std::wstring::npos ||
        lowerPath.find(L"projects") != std::wstring::npos) {
        return "INTERNAL";
    }
    return "RESTRICTED";
}

int ClassificationService::CalculateRiskScore(bool hasPII, const std::string& exposure) const {
    int score = 0;
    if (hasPII) {
        score += 60;  // CONFIDENTIAL base for PII
    }
    if (exposure == "PUBLIC") {
        score += 10;
    }
    if (score > 100) {
        score = 100;
    }
    return score;
}

std::string ClassificationService::GetFileOwnerSid(const std::wstring& filePath) const {
    // Use GetFileSecurity to retrieve the file owner's SID. The caller must
    // have at least read access; on failure we return an empty string so the
    // backend can fall back gracefully.
    SECURITY_DESCRIPTOR* pSD = nullptr;
    DWORD sdSize = 0;

    // First call returns ERROR_INSUFFICIENT_BUFFER with the required size.
    if (!GetFileSecurityW(filePath.c_str(), OWNER_SECURITY_INFORMATION,
                          nullptr, 0, &sdSize) &&
        GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        return "";
    }

    pSD = reinterpret_cast<SECURITY_DESCRIPTOR*>(new BYTE[sdSize]);
    if (!GetFileSecurityW(filePath.c_str(), OWNER_SECURITY_INFORMATION,
                          pSD, sdSize, &sdSize)) {
        delete[] reinterpret_cast<BYTE*>(pSD);
        return "";
    }

    PSID pOwner = nullptr;
    BOOL ownerDefaulted = FALSE;
    if (!GetSecurityDescriptorOwner(pSD, &pOwner, &ownerDefaulted) || pOwner == nullptr) {
        delete[] reinterpret_cast<BYTE*>(pSD);
        return "";
    }

    LPWSTR sidString = nullptr;
    std::string result;
    if (ConvertSidToStringSidW(pOwner, &sidString)) {
        std::wstring wideSid(sidString);
        result.assign(wideSid.begin(), wideSid.end());
        LocalFree(sidString);
    }

    delete[] reinterpret_cast<BYTE*>(pSD);
    return result;
}

void ClassificationService::RunDeepContentInspection(
    const std::wstring& filePath,
    ClassificationResult& result)
{
    // Default exposure for every reported asset.
    std::string exposure = CalculateExposure(filePath);
    result.exposureLevel = exposure;

    // Owner SID for the file (best-effort; empty string on failure).
    result.ownerSid = GetFileOwnerSid(filePath);

    // Extract text only for supported plain-text extensions. Unsupported or
    // binary files return an empty string and are skipped cheaply.
    std::string text = ExtractTextFromFile(filePath);
    if (text.empty()) {
        result.riskScore = CalculateRiskScore(false, exposure);
        result.contentSnippet = "";
        return;
    }

    std::vector<std::string> piiMatches = ScanTextForPII(text);
    if (piiMatches.empty()) {
        result.riskScore = CalculateRiskScore(false, exposure);
        result.contentSnippet = "";
        return;
    }

    // PII found: escalate the classification to CONFIDENTIAL (kept as
    // metadata; the kernel enforcement classification remains the rule result).
    result.classification |= DLP_CLASS_CONFIDENTIAL | DLP_CLASS_PII;
    result.confidence = 100;
    result.isProtected = DLP_IS_PROTECTED_CLASS(result.classification);

    result.riskScore = CalculateRiskScore(true, exposure);

    // Build the content snippet: mask all PII, then cap at 50 characters.
    std::string masked = MaskSensitiveData(text);
    result.contentSnippet = masked.substr(0, kDciSnippetMaxChars);

    LOG_INFO("DCI: PII detected in %ws (%zu findings), risk=%d, exposure=%s, snippet='%s'",
        filePath.c_str(), piiMatches.size(), result.riskScore,
        exposure.c_str(), result.contentSnippet.c_str());
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
    payload["exposure_level"] = result.exposureLevel;
    payload["risk_score"] = result.riskScore;
    payload["content_snippet"] = result.contentSnippet;
    payload["owner_sid"] = result.ownerSid;

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
