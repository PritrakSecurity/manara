#pragma once

#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <unordered_map>
#include <nlohmann/json.hpp>

/**
 * Policy PolicyAction types
 */
enum class PolicyAction {
    ALLOW,   // Permit the operation
    BLOCK,   // Deny the operation (fail-closed)
    LOG,     // Log but allow (audit mode)
    QUARANTINE, // Move to secure location
    ENCRYPT, // Encrypt before allowing
    REDACT   // Remove sensitive content
};

/**
 * PolicyEvent structure for policy evaluation
 */
struct PolicyEvent {
    std::string eventType;      // "file_write", "usb_write", "network_upload", etc.
    std::string operation;      // "READ", "WRITE", "COPY", "UPLOAD", etc.
    std::string sourcePath;     // Source file path
    std::string destinationPath; // Destination path
    std::string application;    // Application name (e.g., "chrome.exe")
    std::string userId;         // User ID
    std::string dataContent;   // File content or data being transferred
    std::unordered_map<std::string, std::string> metadata; // Additional context
};

/**
 * Policy rule structure
 */
struct PolicyRule {
    std::string ruleId;
    std::string name;
    int priority;              // Higher priority wins
    bool enabled;
    PolicyAction PolicyAction;
    nlohmann::json conditions; // JSON conditions
    nlohmann::json exceptions; // JSON exceptions
};

/**
 * Policy Engine
 * Evaluates events against policy rules with fail-closed semantics
 */
class PolicyEngine {
public:
    PolicyEngine();
    ~PolicyEngine();

    /**
     * Load policy rules from JSON
     * @param policyJson Policy JSON string
     * @return true if policy loaded successfully, false otherwise
     */
    bool LoadRules(const std::string& policyJson);

    /**
     * Load policy rules from JSON object
     * @param policy Policy JSON object
     * @return true if policy loaded successfully, false otherwise
     */
    bool LoadRules(const nlohmann::json& policy);

    /**
     * Evaluate PolicyEvent against policy rules
     * @param PolicyEvent PolicyEvent to evaluate
     * @return PolicyAction to take (ALLOW, BLOCK, LOG, etc.)
     */
    PolicyAction EvaluateEvent(const PolicyEvent& PolicyEvent);

    /**
     * Check if policy is loaded
     * @return true if policy loaded, false otherwise
     */
    bool IsPolicyLoaded() const;

    /**
     * Get number of loaded rules
     * @return Number of rules
     */
    size_t GetRuleCount() const;

    /**
     * Clear all rules (defaults to BLOCK for all operations)
     */
    void ClearRules();

private:
    /**
     * Match PolicyEvent against rule conditions
     * @param PolicyEvent PolicyEvent to match
     * @param rule Rule to match against
     * @return true if PolicyEvent matches rule conditions, false otherwise
     */
    bool MatchConditions(const PolicyEvent& PolicyEvent, const PolicyRule& rule);

    /**
     * Check if exception applies to PolicyEvent
     * @param PolicyEvent PolicyEvent to check
     * @param rule Rule containing exceptions
     * @return true if exception applies, false otherwise
     */
    bool CheckExceptions(const PolicyEvent& PolicyEvent, const PolicyRule& rule);

    /**
     * Resolve conflicts when multiple rules match
     * @param matches Vector of matching rules
     * @return PolicyAction to take based on precedence
     */
    PolicyAction ResolveConflict(const std::vector<PolicyRule>& matches);

    /**
     * Match data classification patterns
     * @param content Data content to check
     * @param patterns Pattern definitions from policy
     * @return true if content matches patterns, false otherwise
     */
    bool MatchDataPatterns(const std::string& content, const nlohmann::json& patterns);

    /**
     * Match regex pattern
     * @param content Content to match
     * @param pattern Regex pattern
     * @return true if matches, false otherwise
     */
    bool MatchRegex(const std::string& content, const std::string& pattern);

    /**
     * Match file fingerprint
     * @param content File content
     * @param fingerprints Fingerprint definitions
     * @return true if matches, false otherwise
     */
    bool MatchFingerprint(const std::string& content, const nlohmann::json& fingerprints);

    /**
     * Match context conditions (user, application, time, location)
     * @param PolicyEvent PolicyEvent to match
     * @param context Context conditions from policy
     * @return true if matches, false otherwise
     */
    bool MatchContext(const PolicyEvent& PolicyEvent, const nlohmann::json& context);

    /**
     * Match operation conditions
     * @param PolicyEvent PolicyEvent to match
     * @param operations Operation conditions from policy
     * @return true if matches, false otherwise
     */
    bool MatchOperations(const PolicyEvent& PolicyEvent, const nlohmann::json& operations);

    /**
     * Parse PolicyAction from string
     * @param actionStr PolicyAction string ("ALLOW", "BLOCK", etc.)
     * @return PolicyAction enum value
     */
    PolicyAction ParseAction(const std::string& actionStr);

    // Policy rules (sorted by priority)
    std::vector<PolicyRule> rules_;

    // Compiled regex patterns cache
    std::unordered_map<std::string, std::string> regexCache_;

    // Guards rules_ and regexCache_ against concurrent access from the policy
    // refresh thread and the event-processing thread.
    mutable std::mutex mutex_;
};
