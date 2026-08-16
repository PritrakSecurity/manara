#include "PolicyEngine.h"
#include "../common/utils/logging.h"
#include <regex>
#include <algorithm>
#include <chrono>
#include <iomanip>
#include <sstream>

// Simple regex implementation (for production, use std::regex or PCRE)
#ifdef _WIN32
#include <regex>
#else
#include <regex>
#endif

PolicyEngine::PolicyEngine() {
    // Initialize with empty rules (defaults to BLOCK)
}

PolicyEngine::~PolicyEngine() {
    ClearRules();
}

bool PolicyEngine::LoadRules(const std::string& policyJson) {
    try {
        nlohmann::json policy = nlohmann::json::parse(policyJson);
        return LoadRules(policy);
    } catch (const nlohmann::json::exception& e) {
        LOG_ERROR("Failed to parse policy JSON: %s", e.what());
        return false;
    } catch (const std::exception& e) {
        LOG_ERROR("Exception loading policy: %s", e.what());
        return false;
    }
}

bool PolicyEngine::LoadRules(const nlohmann::json& policy) {
    std::lock_guard<std::mutex> lock(mutex_);

    // Clear existing rules (defaults to BLOCK)
    rules_.clear();
    regexCache_.clear();

    try {
        // Validate policy structure
        if (!policy.contains("rules") || !policy["rules"].is_array()) {
            LOG_ERROR("Policy must contain 'rules' array");
            return false;
        }

        // Parse each rule
        for (const auto& ruleJson : policy["rules"]) {
            PolicyRule rule;

            // Required fields
            if (!ruleJson.contains("rule_id")) {
                LOG_WARNING("Rule missing 'rule_id', skipping");
                continue;
            }
            rule.ruleId = ruleJson["rule_id"].get<std::string>();

            rule.name = ruleJson.value("name", "");
            rule.priority = ruleJson.value("priority", 10);
            rule.enabled = ruleJson.value("enabled", true);

            // Parse action
            std::string actionStr = ruleJson.value("action", "BLOCK");
            rule.PolicyAction = ParseAction(actionStr);

            // Store conditions and exceptions as JSON
            if (ruleJson.contains("conditions")) {
                rule.conditions = ruleJson["conditions"];
            }
            if (ruleJson.contains("exceptions")) {
                rule.exceptions = ruleJson["exceptions"];
            }

            rules_.push_back(rule);
        }

        // Sort rules by priority (higher priority first)
        std::sort(rules_.begin(), rules_.end(), 
            [](const PolicyRule& a, const PolicyRule& b) {
                return a.priority > b.priority;
            });

        LOG_INFO("Loaded %zu policy rules", rules_.size());
        return true;

    } catch (const nlohmann::json::exception& e) {
        LOG_ERROR("JSON exception loading rules: %s", e.what());
        return false;
    } catch (const std::exception& e) {
        LOG_ERROR("Exception loading rules: %s", e.what());
        return false;
    }
}

PolicyAction PolicyEngine::EvaluateEvent(const PolicyEvent& PolicyEvent) {
    std::lock_guard<std::mutex> lock(mutex_);

    // If no rules loaded, default to BLOCK (fail-closed)
    if (rules_.empty()) {
        LOG_WARNING("No policy rules loaded, defaulting to BLOCK (fail-closed)");
        return PolicyAction::BLOCK;
    }

    // Find all matching rules
    std::vector<PolicyRule> matches;
    for (const auto& rule : rules_) {
        if (!rule.enabled) {
            continue;
        }

        if (MatchConditions(PolicyEvent, rule)) {
            // Check if exception applies
            if (CheckExceptions(PolicyEvent, rule)) {
                // Exception applies, skip this rule
                continue;
            }
            matches.push_back(rule);
        }
    }

    // Resolve conflicts and return PolicyAction
    if (matches.empty()) {
        // No rules match, default to BLOCK (fail-closed)
        return PolicyAction::BLOCK;
    }

    return ResolveConflict(matches);
}

bool PolicyEngine::MatchConditions(const PolicyEvent& PolicyEvent, const PolicyRule& rule) {
    if (rule.conditions.empty()) {
        return false;
    }

    // Match data classification
    if (rule.conditions.contains("data_classification")) {
        const auto& dataClass = rule.conditions["data_classification"];
        
        if (dataClass.contains("patterns")) {
            if (!MatchDataPatterns(PolicyEvent.dataContent, dataClass["patterns"])) {
                return false;
            }
        }

        if (dataClass.contains("fingerprints")) {
            if (!MatchFingerprint(PolicyEvent.dataContent, dataClass["fingerprints"])) {
                return false;
            }
        }
    }

    // Match operations
    if (rule.conditions.contains("operations")) {
        if (!MatchOperations(PolicyEvent, rule.conditions["operations"])) {
            return false;
        }
    }

    // Match context
    if (rule.conditions.contains("context")) {
        if (!MatchContext(PolicyEvent, rule.conditions["context"])) {
            return false;
        }
    }

    return true;
}

bool PolicyEngine::CheckExceptions(const PolicyEvent& PolicyEvent, const PolicyRule& rule) {
    if (rule.exceptions.empty() || !rule.exceptions.is_array()) {
        return false;
    }

    for (const auto& exception : rule.exceptions) {
        // Check if exception conditions match
        bool matches = true;

        if (exception.contains("condition")) {
            const auto& condition = exception["condition"];

            // Check user
            if (condition.contains("users")) {
                const auto& users = condition["users"];
                if (users.contains("include")) {
                    const auto& includeList = users["include"];
                    bool found = false;
                    for (const auto& user : includeList) {
                        if (user.get<std::string>() == PolicyEvent.userId) {
                            found = true;
                            break;
                        }
                    }
                    if (!found) matches = false;
                }
            }

            // Check application
            if (condition.contains("applications")) {
                const auto& apps = condition["applications"];
                if (apps.contains("include")) {
                    const auto& includeList = apps["include"];
                    bool found = false;
                    for (const auto& app : includeList) {
                        if (app.get<std::string>() == PolicyEvent.application) {
                            found = true;
                            break;
                        }
                    }
                    if (!found) matches = false;
                }
            }
        }

        if (matches) {
            return true; // Exception applies
        }
    }

    return false; // No exceptions apply
}

PolicyAction PolicyEngine::ResolveConflict(const std::vector<PolicyRule>& matches) {
    // Rules are already sorted by priority
    // First matching rule wins (highest priority)
    // Within same priority, BLOCK takes precedence over ALLOW

    // Find highest priority
    int maxPriority = matches[0].priority;

    // Collect all rules with max priority
    std::vector<PolicyRule> topPriorityRules;
    for (const auto& rule : matches) {
        if (rule.priority == maxPriority) {
            topPriorityRules.push_back(rule);
        }
    }

    // If multiple rules with same priority, BLOCK takes precedence
    for (const auto& rule : topPriorityRules) {
        if (rule.PolicyAction == PolicyAction::BLOCK) {
            return PolicyAction::BLOCK;
        }
    }

    // Return first PolicyAction (should be ALLOW if we got here)
    return topPriorityRules[0].PolicyAction;
}

bool PolicyEngine::MatchDataPatterns(const std::string& content, const nlohmann::json& patterns) {
    if (!patterns.is_array()) {
        return false;
    }

    for (const auto& pattern : patterns) {
        if (!pattern.contains("type") || !pattern.contains("pattern")) {
            continue;
        }

        std::string type = pattern["type"].get<std::string>();
        std::string patternStr = pattern["pattern"].get<std::string>();

        if (type == "regex") {
            if (MatchRegex(content, patternStr)) {
                return true;
            }
        }
    }

    return false;
}

bool PolicyEngine::MatchRegex(const std::string& content, const std::string& pattern) {
    try {
        std::regex regexPattern(pattern, std::regex_constants::ECMAScript | std::regex_constants::icase);
        return std::regex_search(content, regexPattern);
    } catch (const std::regex_error& e) {
        LOG_WARNING("Invalid regex pattern '%s': %s", pattern.c_str(), e.what());
        return false;
    }
}

bool PolicyEngine::MatchFingerprint(const std::string& content, const nlohmann::json& fingerprints) {
    // Simple fingerprint matching (should use SHA-256 in production)
    // For now, just check if content hash matches
    if (!fingerprints.is_array()) {
        return false;
    }

    // Calculate content hash (simplified - should use proper hashing)
    std::hash<std::string> hasher;
    size_t contentHash = hasher(content);

    for (const auto& fingerprint : fingerprints) {
        if (fingerprint.contains("hash")) {
            // Compare hashes (simplified)
            std::string expectedHash = fingerprint["hash"].get<std::string>();
            // In production, would use SHA-256 and compare properly
        }
    }

    return false; // Simplified implementation
}

bool PolicyEngine::MatchContext(const PolicyEvent& PolicyEvent, const nlohmann::json& context) {
    // Match user
    if (context.contains("users")) {
        const auto& users = context["users"];
        if (users.contains("include")) {
            const auto& includeList = users["include"];
            bool found = false;
            for (const auto& user : includeList) {
                if (user.get<std::string>() == PolicyEvent.userId) {
                    found = true;
                    break;
                }
            }
            if (!found) return false;
        }
        if (users.contains("exclude")) {
            const auto& excludeList = users["exclude"];
            for (const auto& user : excludeList) {
                if (user.get<std::string>() == PolicyEvent.userId) {
                    return false; // User is excluded
                }
            }
        }
    }

    // Match application
    if (context.contains("applications")) {
        const auto& apps = context["applications"];
        if (apps.contains("include")) {
            const auto& includeList = apps["include"];
            bool found = false;
            for (const auto& app : includeList) {
                if (app.get<std::string>() == PolicyEvent.application) {
                    found = true;
                    break;
                }
            }
            if (!found) return false;
        }
        if (apps.contains("exclude")) {
            const auto& excludeList = apps["exclude"];
            for (const auto& app : excludeList) {
                if (app.get<std::string>() == PolicyEvent.application) {
                    return false; // Application is excluded
                }
            }
        }
    }

    // Match time schedule (simplified - would check current time)
    if (context.contains("time")) {
        // Time-based matching would be implemented here
        // For now, always match
    }

    return true;
}

bool PolicyEngine::MatchOperations(const PolicyEvent& PolicyEvent, const nlohmann::json& operations) {
    // Match file operations
    if (operations.contains("file")) {
        const auto& fileOps = operations["file"];
        if (fileOps.is_array()) {
            bool found = false;
            for (const auto& op : fileOps) {
                std::string opStr = op.get<std::string>();
                if ((opStr == "WRITE" && PolicyEvent.operation == "WRITE") ||
                    (opStr == "READ" && PolicyEvent.operation == "READ") ||
                    (opStr == "COPY" && PolicyEvent.operation == "COPY")) {
                    found = true;
                    break;
                }
            }
            if (!found) return false;
        }
    }

    // Match device operations
    if (operations.contains("device")) {
        const auto& deviceOps = operations["device"];
        if (deviceOps.is_array()) {
            bool found = false;
            for (const auto& op : deviceOps) {
                std::string opStr = op.get<std::string>();
                if (opStr == "USB_WRITE" && PolicyEvent.eventType == "usb_write") {
                    found = true;
                    break;
                }
            }
            if (!found) return false;
        }
    }

    // Match network operations
    if (operations.contains("network")) {
        const auto& networkOps = operations["network"];
        if (networkOps.is_array()) {
            bool found = false;
            for (const auto& op : networkOps) {
                std::string opStr = op.get<std::string>();
                if ((opStr == "UPLOAD" && PolicyEvent.operation == "UPLOAD") ||
                    (opStr == "DOWNLOAD" && PolicyEvent.operation == "DOWNLOAD")) {
                    found = true;
                    break;
                }
            }
            if (!found) return false;
        }
    }

    return true;
}

PolicyAction PolicyEngine::ParseAction(const std::string& actionStr) {
    if (actionStr == "ALLOW") return PolicyAction::ALLOW;
    if (actionStr == "BLOCK") return PolicyAction::BLOCK;
    if (actionStr == "LOG" || actionStr == "AUDIT") return PolicyAction::LOG;
    if (actionStr == "QUARANTINE") return PolicyAction::QUARANTINE;
    if (actionStr == "ENCRYPT") return PolicyAction::ENCRYPT;
    if (actionStr == "REDACT") return PolicyAction::REDACT;

    // Default to BLOCK (fail-closed)
    return PolicyAction::BLOCK;
}

void PolicyEngine::ClearRules() {
    std::lock_guard<std::mutex> lock(mutex_);
    rules_.clear();
    regexCache_.clear();
}

bool PolicyEngine::IsPolicyLoaded() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return !rules_.empty();
}

size_t PolicyEngine::GetRuleCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return rules_.size();
}
