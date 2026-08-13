package classification

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ClassificationRule represents a user-defined rule
type ClassificationRule struct {
	ID                   int       `json:"id"`
	Name                 string    `json:"name"`
	Description          string    `json:"description"`
	Enabled              bool      `json:"enabled"`
	Priority             int       `json:"priority"`
	ConditionField       string    `json:"condition_field"`
	ConditionOperator    string    `json:"condition_operator"`
	ConditionValue       string    `json:"condition_value"`
	ActionType           string    `json:"action_type"`
	ActionClassification string    `json:"action_classification"`
	CreatedBy            string    `json:"created_by"`
	CreatedAt            time.Time `json:"created_at"`
	UpdatedAt            time.Time `json:"updated_at"`
	IsSystem             bool      `json:"is_system"`
}

// RuleEvaluationResult holds the result of rule evaluation
type RuleEvaluationResult struct {
	Matched           bool
	RuleID            int
	RuleName          string
	NewClassification string
	Explanation       string
}

// RuleEngine evaluates classification rules
type RuleEngine struct {
	db    *sql.DB
	rules []ClassificationRule
	mu    sync.RWMutex
}

// NewRuleEngine creates a new rule engine
func NewRuleEngine(db *sql.DB) *RuleEngine {
	engine := &RuleEngine{
		db:    db,
		rules: []ClassificationRule{},
	}
	if db != nil {
		engine.loadRulesFromDB()
	}
	return engine
}

// loadRulesFromDB loads all enabled rules from database
func (re *RuleEngine) loadRulesFromDB() {
	if re.db == nil {
		return
	}

	re.mu.Lock()
	defer re.mu.Unlock()

	re.rules = []ClassificationRule{}

	rows, err := re.db.Query(`
		SELECT id, name, description, enabled, priority, condition_field, 
		       condition_operator, condition_value, action_type, action_classification,
		       created_by, created_at, updated_at, is_system
		FROM classification_rules 
		WHERE enabled = TRUE
		ORDER BY priority ASC
	`)
	if err != nil {
		fmt.Printf("[ERROR] Failed to load rules: %v\n", err)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var rule ClassificationRule
		err := rows.Scan(
			&rule.ID, &rule.Name, &rule.Description, &rule.Enabled, &rule.Priority,
			&rule.ConditionField, &rule.ConditionOperator, &rule.ConditionValue,
			&rule.ActionType, &rule.ActionClassification, &rule.CreatedBy,
			&rule.CreatedAt, &rule.UpdatedAt, &rule.IsSystem,
		)
		if err != nil {
			fmt.Printf("[ERROR] Failed to scan rule: %v\n", err)
			continue
		}
		re.rules = append(re.rules, rule)
	}

	fmt.Printf("[RULE-ENGINE] Loaded %d classification rules\n", len(re.rules))
}

// Evaluate checks file against all rules and returns matching rule
// fileContent is the actual file content from the agent (empty string if not available)
func (re *RuleEngine) Evaluate(filePath string, phaseResult EngineClassificationResult, fileContent string) RuleEvaluationResult {
	re.mu.RLock()
	rulesCopy := make([]ClassificationRule, len(re.rules))
	copy(rulesCopy, re.rules)
	re.mu.RUnlock()

	// Rules are already sorted by priority from loadRulesFromDB
	for _, rule := range rulesCopy {
		if !rule.Enabled {
			continue
		}

		if re.evaluateCondition(&rule, filePath, phaseResult, fileContent) {
			return RuleEvaluationResult{
				Matched:           true,
				RuleID:            rule.ID,
				RuleName:          rule.Name,
				NewClassification: rule.ActionClassification,
				Explanation:       fmt.Sprintf("Rule '%s' triggered", rule.Name),
			}
		}
	}

	// No rule matched
	return RuleEvaluationResult{
		Matched:           false,
		RuleID:            -1,
		RuleName:          "",
		NewClassification: phaseResult.Classification,
		Explanation:       "No rules matched, using Phase 0-4 result",
	}
}

// evaluateCondition checks if a single rule's condition is met
func (re *RuleEngine) evaluateCondition(rule *ClassificationRule, filePath string, phaseResult EngineClassificationResult, fileContent string) bool {
	switch rule.ConditionField {
	case "keyword":
		return re.evaluateKeyword(rule, filePath, fileContent)
	case "file_extension":
		return re.evaluateFileExtension(rule, filePath)
	case "file_size":
		return re.evaluateFileSize(rule, filePath)
	case "directory_path":
		return re.evaluateDirectoryPath(rule, filePath)
	case "content_pattern":
		return re.evaluateContentPattern(rule, filePath, fileContent)
	default:
		return false
	}
}

// evaluateKeyword checks filename and file content against keyword rule
// fileContent is provided from the agent (not read from disk)
func (re *RuleEngine) evaluateKeyword(rule *ClassificationRule, filePath string, fileContent string) bool {
	filename := strings.ToLower(filepath.Base(filePath))
	value := strings.ToLower(rule.ConditionValue)

	// First check filename
	switch rule.ConditionOperator {
	case "equals":
		if filename == value {
			fmt.Printf("[RULE-MATCH] Rule '%s' matched on filename (equals)\n", rule.Name)
			return true
		}
	case "contains":
		if strings.Contains(filename, value) {
			fmt.Printf("[RULE-MATCH] Rule '%s' matched on filename (contains)\n", rule.Name)
			return true
		}
	case "matches_regex":
		if regex, err := regexp.Compile(value); err == nil {
			if regex.MatchString(filename) {
				fmt.Printf("[RULE-MATCH] Rule '%s' matched on filename (regex)\n", rule.Name)
				return true
			}
		}
	}

	// Check file content if available (sent from agent)
	if fileContent != "" && (rule.ConditionOperator == "contains" || rule.ConditionOperator == "matches_regex") {
		contentStr := strings.ToLower(fileContent)

		if rule.ConditionOperator == "contains" {
			if strings.Contains(contentStr, value) {
				fmt.Printf("[RULE-MATCH] Rule '%s' matched on file CONTENT (contains '%s')\n", rule.Name, value)
				return true
			}
		} else if rule.ConditionOperator == "matches_regex" {
			if regex, err := regexp.Compile(value); err == nil {
				if regex.MatchString(contentStr) {
					fmt.Printf("[RULE-MATCH] Rule '%s' matched on file CONTENT (regex)\n", rule.Name)
					return true
				}
			}
		}
	}

	// If no content available, try reading from disk as fallback (for local files)
	if fileContent == "" && (rule.ConditionOperator == "contains" || rule.ConditionOperator == "matches_regex") {
		if content, err := os.ReadFile(filePath); err == nil {
			contentStr := strings.ToLower(string(content))

			if rule.ConditionOperator == "contains" {
				if strings.Contains(contentStr, value) {
					fmt.Printf("[RULE-MATCH] Rule '%s' matched on file CONTENT from disk (contains)\n", rule.Name)
					return true
				}
			} else if rule.ConditionOperator == "matches_regex" {
				if regex, err := regexp.Compile(value); err == nil {
					if regex.MatchString(contentStr) {
						fmt.Printf("[RULE-MATCH] Rule '%s' matched on file CONTENT from disk (regex)\n", rule.Name)
						return true
					}
				}
			}
		}
	}

	fmt.Printf("[RULE-NO-MATCH] Rule '%s' did NOT match filename='%s' hasContent=%v\n", rule.Name, filename, fileContent != "")
	return false
}

// evaluateFileExtension checks file extension
func (re *RuleEngine) evaluateFileExtension(rule *ClassificationRule, filePath string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))
	value := strings.ToLower(rule.ConditionValue)

	switch rule.ConditionOperator {
	case "equals":
		// Handle both ".txt" and "txt" formats
		if !strings.HasPrefix(value, ".") {
			value = "." + value
		}
		return ext == value
	case "in_list":
		// Parse comma-separated list
		extensions := strings.Split(value, ",")
		for _, e := range extensions {
			e = strings.TrimSpace(e)
			if !strings.HasPrefix(e, ".") {
				e = "." + e
			}
			if ext == strings.ToLower(e) {
				return true
			}
		}
		return false
	default:
		return false
	}
}

// evaluateFileSize checks file size in MB
func (re *RuleEngine) evaluateFileSize(rule *ClassificationRule, filePath string) bool {
	info, err := os.Stat(filePath)
	if err != nil {
		return false
	}

	fileSizeMB := info.Size() / (1024 * 1024)
	var conditionSizeMB int64
	_, err = fmt.Sscanf(rule.ConditionValue, "%d", &conditionSizeMB)
	if err != nil {
		return false
	}

	switch rule.ConditionOperator {
	case "gt":
		return fileSizeMB > conditionSizeMB
	case "lt":
		return fileSizeMB < conditionSizeMB
	case "equals":
		return fileSizeMB == conditionSizeMB
	default:
		return false
	}
}

// evaluateDirectoryPath checks if file is in a specific directory
func (re *RuleEngine) evaluateDirectoryPath(rule *ClassificationRule, filePath string) bool {
	dir := strings.ToLower(filepath.Dir(filePath))
	value := strings.ToLower(rule.ConditionValue)

	switch rule.ConditionOperator {
	case "equals":
		return dir == value
	case "contains":
		return strings.Contains(dir, value)
	case "matches_regex":
		if regex, err := regexp.Compile(value); err == nil {
			return regex.MatchString(dir)
		}
		return false
	default:
		return false
	}
}

// evaluateContentPattern checks file content
func (re *RuleEngine) evaluateContentPattern(rule *ClassificationRule, filePath string, fileContent string) bool {
	var contentStr string

	// Use provided content if available, otherwise read from disk
	if fileContent != "" {
		contentStr = strings.ToLower(fileContent)
	} else {
		content, err := os.ReadFile(filePath)
		if err != nil {
			return false
		}
		contentStr = strings.ToLower(string(content))
	}

	value := strings.ToLower(rule.ConditionValue)

	switch rule.ConditionOperator {
	case "contains":
		return strings.Contains(contentStr, value)
	case "matches_regex":
		if regex, err := regexp.Compile(value); err == nil {
			return regex.MatchString(contentStr)
		}
		return false
	default:
		return false
	}
}

// GetAllRules returns all rules
func (re *RuleEngine) GetAllRules() []ClassificationRule {
	re.mu.RLock()
	defer re.mu.RUnlock()
	return append([]ClassificationRule{}, re.rules...)
}

// AddRule adds a new rule to database and memory
func (re *RuleEngine) AddRule(rule ClassificationRule) error {
	if re.db == nil {
		return fmt.Errorf("database not available")
	}

	_, err := re.db.Exec(`
		INSERT INTO classification_rules 
		(name, description, enabled, priority, condition_field, condition_operator,
		 condition_value, action_type, action_classification, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`,
		rule.Name, rule.Description, rule.Enabled, rule.Priority,
		rule.ConditionField, rule.ConditionOperator, rule.ConditionValue,
		rule.ActionType, rule.ActionClassification, rule.CreatedBy,
	)

	if err == nil {
		re.loadRulesFromDB() // Reload rules
	}

	return err
}

// UpdateRule updates an existing rule
func (re *RuleEngine) UpdateRule(rule ClassificationRule) error {
	if re.db == nil {
		return fmt.Errorf("database not available")
	}

	_, err := re.db.Exec(`
		UPDATE classification_rules SET 
		name = $1, description = $2, enabled = $3, priority = $4,
		condition_field = $5, condition_operator = $6, condition_value = $7,
		action_type = $8, action_classification = $9, updated_at = CURRENT_TIMESTAMP
		WHERE id = $10
	`,
		rule.Name, rule.Description, rule.Enabled, rule.Priority,
		rule.ConditionField, rule.ConditionOperator, rule.ConditionValue,
		rule.ActionType, rule.ActionClassification, rule.ID,
	)

	if err == nil {
		re.loadRulesFromDB() // Reload rules
	}

	return err
}

// DeleteRule deletes a rule by ID
func (re *RuleEngine) DeleteRule(ruleID int) error {
	if re.db == nil {
		return fmt.Errorf("database not available")
	}

	_, err := re.db.Exec("DELETE FROM classification_rules WHERE id = $1", ruleID)

	if err == nil {
		re.loadRulesFromDB() // Reload rules
	}

	return err
}

// ReloadRules reloads all rules from database
func (re *RuleEngine) ReloadRules() {
	re.loadRulesFromDB()
}

// SetRules sets rules directly (for in-memory operation without database)
func (re *RuleEngine) SetRules(rules []ClassificationRule) {
	re.mu.Lock()
	defer re.mu.Unlock()
	re.rules = make([]ClassificationRule, len(rules))
	copy(re.rules, rules)
	fmt.Printf("[RULE-ENGINE] Loaded %d classification rules (in-memory)\n", len(re.rules))
}
