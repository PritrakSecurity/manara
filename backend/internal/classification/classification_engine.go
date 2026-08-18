package classification

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
)

// RiskLevel defines the severity of risk
type RiskLevel string

const (
	RiskNone       RiskLevel = "NONE"
	RiskLow        RiskLevel = "LOW"
	RiskMediumHigh RiskLevel = "MEDIUM_HIGH"
	RiskCritical   RiskLevel = "CRITICAL"
)

// Classification levels
type Classification string

const (
	ClassPublic       Classification = "PUBLIC"
	ClassInternal     Classification = "INTERNAL"
	ClassConfidential Classification = "CONFIDENTIAL"
	ClassRestricted   Classification = "RESTRICTED"
)

// EngineClassificationResult is the output of the classification engine
type EngineClassificationResult struct {
	Classification string    `json:"classification"`           // PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED
	Score          float64   `json:"score"`                    // 0-100
	Confidence     float64   `json:"confidence"`               // 0-100
	Explanation    string    `json:"explanation"`              // Why this classification
	RiskLevel      string    `json:"risk_level"`               // NONE, LOW, MEDIUM_HIGH, CRITICAL
	ElapsedMs      int       `json:"elapsed_ms"`               // Classification latency
	RuleTriggered  string    `json:"rule_triggered,omitempty"` // Name of rule that triggered, if any
	Findings       []Finding `json:"findings,omitempty"`       // Structured findings from Phase 2 detections
}

var (
	apiKeyRegex       = regexp.MustCompile(`(?i)(?:api_key|apikey|api-key|secret|access_token)[\s:=]+([a-zA-Z0-9_\-]{32,})`)
	dbConnStringRegex = regexp.MustCompile(`(?i)(?:mysql|postgres|mongodb|sqlserver)://`)
	jwtRegex          = regexp.MustCompile(`eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+`)
)

// ClassificationEngine handles file classification
type ClassificationEngine struct {
	validators   PatternValidators
	ruleEngine   *RuleEngine
	orchestrator *Orchestrator
}

// NewClassificationEngine creates a new engine
func NewClassificationEngine() *ClassificationEngine {
	return NewEngineWithProvider(nil)
}

// NewEngineWithProvider creates a classification engine wired to the given
// optional analysis provider. When provider is nil, the NoOpProvider-backed
// orchestrator is used so behavior stays fully deterministic.
func NewEngineWithProvider(provider AnalysisProvider) *ClassificationEngine {
	orchestrator := NewOrchestrator(NoOpProvider{})
	if provider != nil {
		orchestrator = NewOrchestrator(provider)
	}
	return &ClassificationEngine{
		validators:   NewPatternValidators(),
		ruleEngine:   nil,
		orchestrator: orchestrator,
	}
}

// SetRuleEngine sets the rule engine for classification
func (ce *ClassificationEngine) SetRuleEngine(engine *RuleEngine) {
	ce.ruleEngine = engine
}

// SetOrchestrator sets the Phase 2.5 analysis orchestrator (optional AI
// sidecar). It defaults to the NoOpProvider-backed orchestrator, which
// abstains and keeps behavior fully deterministic.
func (ce *ClassificationEngine) SetOrchestrator(o *Orchestrator) {
	ce.orchestrator = o
}

// Classify classifies a file based on path and content
// This supports remote agent files that may not exist on the backend server
func (ce *ClassificationEngine) Classify(filePath string) EngineClassificationResult {
	start := time.Now()

	// Track content for rule evaluation even if fast path returns early
	content := ""

	fileSize := int64(0)
	fileInfo, err := os.Stat(filePath)
	if err == nil {
		fileSize = fileInfo.Size()
		content = ce.readFileContent(filePath, 1_000_000) // 1MB max
	}
	// If file not found, continue with fileSize=0 (remote file scenario)

	// Phase 0: Fast Filter
	phase0Score, decided := ce.phase0FastFilter(filePath, fileSize)
	if decided {
		result := ce.phase4Decision(phase0Score)

		// Allow rule engine to override even when fast-filter short circuits
		if ce.ruleEngine != nil {
			ruleResult := ce.ruleEngine.Evaluate(filePath, result, content)
			if ruleResult.Matched {
				result.Classification = ruleResult.NewClassification
				result.Score = 100.0
				result.Confidence = 100.0
				result.Explanation = ruleResult.Explanation
				result.RuleTriggered = ruleResult.RuleName
			}
		}

		result.ElapsedMs = int(time.Since(start).Milliseconds())
		return result
	}

	// Phase 1: Pre-Analysis
	phase1Score := ce.phase1PreAnalysis(filePath)

	// Phase 2: Content Patterns
	phase2Score := ce.phase2ContentPatterns(content)
	findings := ce.collectPhase2Findings(content)

	// Combine scores
	currentScore := phase1Score + phase2Score

	// Phase 2.5: AI Sidecar (optional, if 50 <= score < 90)
	phase25Adjustment := float64(0)
	if currentScore >= 50 && currentScore < 90 {
		// Optional AI-provider findings are merged against the deterministic
		// Phase 2 findings. MergeFindings guarantees hard findings can never
		// be deleted or downgraded, even if the provider times out or is
		// unavailable (in which case it returns no findings).
		findings = MergeFindings(findings, ce.runPhase25(context.Background(), content, findings, filePath).Findings)
	}
	currentScore += phase25Adjustment

	// Phase 3: Context Logic
	phase3Adjustment := ce.phase3ContextLogic(filePath, content)
	currentScore += phase3Adjustment

	// Phase 4: Final Decision
	result := ce.phase4Decision(currentScore)
	result.Findings = findings

	// Phase 5: Rule Engine Evaluation (NEW FOR V3.0)
	if ce.ruleEngine != nil {
		ruleResult := ce.ruleEngine.Evaluate(filePath, result, content)
		if ruleResult.Matched {
			// Rule was triggered - override Phase 0-4 result
			result.Classification = ruleResult.NewClassification
			result.Score = 100.0
			result.Confidence = 100.0
			result.Explanation = ruleResult.Explanation
			result.RuleTriggered = ruleResult.RuleName
		}
	}

	result.ElapsedMs = int(time.Since(start).Milliseconds())

	return result
}

// ClassifyWithContent classifies based on path and provided content (for remote agent files)
func (ce *ClassificationEngine) ClassifyWithContent(filePath string, content string, fileSize int64) EngineClassificationResult {
	start := time.Now()

	// Phase 0: Fast Filter
	phase0Score, decided := ce.phase0FastFilter(filePath, fileSize)
	if decided {
		result := ce.phase4Decision(phase0Score)

		// Allow rule engine to override even when fast-filter short circuits
		if ce.ruleEngine != nil {
			ruleResult := ce.ruleEngine.Evaluate(filePath, result, content)
			if ruleResult.Matched {
				result.Classification = ruleResult.NewClassification
				result.Score = 100.0
				result.Confidence = 100.0
				result.Explanation = ruleResult.Explanation
				result.RuleTriggered = ruleResult.RuleName
			}
		}

		result.ElapsedMs = int(time.Since(start).Milliseconds())
		return result
	}

	// Phase 1: Pre-Analysis
	phase1Score := ce.phase1PreAnalysis(filePath)

	// Phase 2: Content Patterns (using provided content)
	phase2Score := ce.phase2ContentPatterns(content)
	findings := ce.collectPhase2Findings(content)

	// Combine scores
	currentScore := phase1Score + phase2Score

	// Phase 2.5: AI Sidecar (optional, if 50 <= score < 90)
	phase25Adjustment := float64(0)
	if currentScore >= 50 && currentScore < 90 {
		findings = MergeFindings(findings, ce.runPhase25(context.Background(), content, findings, filePath).Findings)
	}
	currentScore += phase25Adjustment

	// Phase 3: Context Logic
	phase3Adjustment := ce.phase3ContextLogic(filePath, content)
	currentScore += phase3Adjustment

	// Phase 4: Final Decision
	result := ce.phase4Decision(currentScore)
	result.Findings = findings

	// Phase 5: Rule Engine Evaluation (NEW FOR V3.0)
	if ce.ruleEngine != nil {
		ruleResult := ce.ruleEngine.Evaluate(filePath, result, content)
		if ruleResult.Matched {
			// Rule was triggered - override Phase 0-4 result
			result.Classification = ruleResult.NewClassification
			result.Score = 100.0
			result.Confidence = 100.0
			result.Explanation = ruleResult.Explanation
			result.RuleTriggered = ruleResult.RuleName
		}
	}

	result.ElapsedMs = int(time.Since(start).Milliseconds())

	return result
}

// phase0FastFilter - instant decisions based on extension and size
func (ce *ClassificationEngine) phase0FastFilter(filePath string, fileSize int64) (float64, bool) {
	instantBlock := []string{".key", ".pem", ".p12", ".pfx", ".ppk", ".sql", ".sql.bak", ".env", ".env.production", ".gpg", ".aes", ".ssh"}
	// NOTE: We do NOT include .txt in instantAllow because we need to scan content for sensitive data like CVV
	instantAllow := []string{".log", ".tmp", ".cache"}

	ext := strings.ToLower(filepath.Ext(filePath))

	// Rule 1: Empty file
	if fileSize == 0 {
		return 0, true // PUBLIC
	}

	// Rule 2: Instant BLOCK
	for _, e := range instantBlock {
		if ext == e {
			return 100, true // RESTRICTED
		}
	}

	// Rule 3: Instant ALLOW
	for _, e := range instantAllow {
		if ext == e {
			return 0, true // PUBLIC
		}
	}

	// Rule 4: Large SQL dump
	if fileSize > 100_000_000 && (strings.HasSuffix(filePath, ".sql") || strings.HasSuffix(filePath, ".db")) {
		return 100, true // RESTRICTED
	}

	// Rule 5: Sensitive filenames
	filename := strings.ToLower(filepath.Base(filePath))
	if strings.Contains(filename, "password") || strings.Contains(filename, "secret") || strings.Contains(filename, "api_key") {
		return 95, true // RESTRICTED
	}

	// No fast decision
	return -1, false // Continue to next phase
}

// phase1PreAnalysis - scoring based on filename, directory, extension
func (ce *ClassificationEngine) phase1PreAnalysis(filePath string) float64 {
	score := float64(0)

	filename := strings.ToLower(filepath.Base(filePath))
	dir := strings.ToLower(filePath)
	ext := strings.ToLower(filepath.Ext(filePath))

	// Filename scoring
	if strings.Contains(filename, "payroll") {
		score += 12
	}
	if strings.Contains(filename, "salary") {
		score += 12
	}
	if strings.Contains(filename, "customer") {
		score += 8
	}
	if strings.Contains(filename, "invoice") {
		score += 8
	}
	if strings.Contains(filename, "pii") {
		score += 18
	}
	if strings.Contains(filename, "ssn") {
		score += 25
	}
	if strings.Contains(filename, "credit_card") {
		score += 20
	}
	if strings.Contains(filename, "password") {
		score += 15
	}
	if strings.Contains(filename, "secret") {
		score += 15
	}

	// Directory scoring
	if strings.Contains(dir, "\\hr") || strings.Contains(dir, "/hr") {
		score += 10
	}
	if strings.Contains(dir, "\\finance") || strings.Contains(dir, "/finance") {
		score += 12
	}
	if strings.Contains(dir, "\\legal") || strings.Contains(dir, "/legal") {
		score += 10
	}
	if strings.Contains(dir, "\\executive") || strings.Contains(dir, "/executive") {
		score += 15
	}
	if strings.Contains(dir, "\\secret") || strings.Contains(dir, "/secret") {
		score += 20
	}
	if strings.Contains(dir, "\\classified") || strings.Contains(dir, "/classified") {
		score += 20
	}

	// Extension scoring
	if ext == ".xlsx" || ext == ".csv" || ext == ".pdf" {
		score += 5
	}
	if ext == ".sql" || ext == ".sql.bak" {
		score += 30
	}

	return score
}

// phase2ContentPatterns - regex pattern matching for PII and secrets
func (ce *ClassificationEngine) phase2ContentPatterns(content string) float64 {
	score := float64(0)

	// Credit cards
	ccMatches := ce.validators.FindCreditCards(content)
	score += float64(len(ccMatches)) * 20

	// SSN
	ssnMatches := ce.validators.FindSSNs(content)
	score += float64(len(ssnMatches)) * 25

	// French NIR
	nirMatches := ce.validators.FindFrenchNIRs(content)
	score += float64(len(nirMatches)) * 35

	// IBAN
	ibanMatches := ce.validators.FindIBANs(content)
	score += float64(len(ibanMatches)) * 18

	// Secrets
	secretScores := ce.phase2Secrets(content)
	score += secretScores

	// Keywords
	keywordScores := ce.phase2Keywords(content)
	score += keywordScores

	return score
}

// phase2Secrets - detect API keys, tokens, etc.
func (ce *ClassificationEngine) phase2Secrets(content string) float64 {
	score := float64(0)
	lowerContent := strings.ToLower(content)

	// AWS Keys
	if matched, _ := regexp.MatchString(`\bAKIA[0-9A-Z]{16}\b`, content); matched {
		score += 100 // INSTANT BLOCK
	}

	// GitHub tokens
	if matched, _ := regexp.MatchString(`ghp_[0-9a-zA-Z]{36}`, content); matched {
		score += 100
	}

	// Private key blocks
	if matched, _ := regexp.MatchString(`-----BEGIN (?:RSA|DSA|EC|OPENSSH|ENCRYPTED) PRIVATE KEY-----`, content); matched {
		score += 100
	}

	// Generic API keys
	if idx := apiKeyRegex.FindStringIndex(content); idx != nil {
		if !ce.isSuppressedByLocalContext(content, idx) {
			score += 70
		}
	}

	// Database connection strings
	if idx := dbConnStringRegex.FindStringIndex(content); idx != nil {
		if !ce.isSuppressedByLocalContext(content, idx) {
			score += 80
		}
	}

	// Stripe keys
	if matched, _ := regexp.MatchString(`sk_live_[0-9a-zA-Z]{24}`, content); matched {
		score += 100 // INSTANT BLOCK for live keys
	}

	// JWT tokens
	if idx := jwtRegex.FindStringIndex(content); idx != nil {
		if !ce.isSuppressedByLocalContext(content, idx) {
			score += 50
		}
	}

	// Common keywords that indicate credentials
	if strings.Contains(lowerContent, "password") {
		score += 15
	}
	if strings.Contains(lowerContent, "api_key") || strings.Contains(lowerContent, "apikey") {
		score += 20
	}
	if strings.Contains(lowerContent, "secret") {
		score += 15
	}

	return score
}

// collectPhase2Findings builds structured findings from the deterministic
// Phase 2 detectors. Structurally validated evidence (Luhn-valid credit
// cards, validated SSNs, NIRs and IBANs) is marked as hard evidence that
// optional providers can never delete or downgrade. Regex-only detections
// (API keys, DB connection strings, JWTs) are contextual and non-hard.
func (ce *ClassificationEngine) collectPhase2Findings(content string) []Finding {
	var findings []Finding

	for _, m := range ce.validators.FindCreditCardIndexes(content) {
		findings = append(findings, newFinding("credit_card", "", "luhn_validator", m[0], m[1], true, 1.0, EvidenceHardValidated))
	}
	for _, m := range ce.validators.FindSSNIndexes(content) {
		findings = append(findings, newFinding("ssn", "", "ssn_validator", m[0], m[1], true, 1.0, EvidenceHardValidated))
	}
	for _, m := range ce.validators.FindFrenchNIRIndexes(content) {
		findings = append(findings, newFinding("french_nir", "", "nir_validator", m[0], m[1], true, 1.0, EvidenceHardValidated))
	}
	for _, m := range ce.validators.FindIBANIndexes(content) {
		findings = append(findings, newFinding("iban", "", "iban_validator", m[0], m[1], true, 1.0, EvidenceHardValidated))
	}

	for _, m := range apiKeyRegex.FindAllStringIndex(content, -1) {
		if ce.isSuppressedByLocalContext(content, m) {
			continue
		}
		findings = append(findings, newFinding("secret", "api_key", "api_key_regex", m[0], m[1], false, 0.9, EvidenceContextual))
	}
	for _, m := range dbConnStringRegex.FindAllStringIndex(content, -1) {
		if ce.isSuppressedByLocalContext(content, m) {
			continue
		}
		findings = append(findings, newFinding("secret", "db_connection_string", "db_conn_regex", m[0], m[1], false, 0.9, EvidenceContextual))
	}
	for _, m := range jwtRegex.FindAllStringIndex(content, -1) {
		if ce.isSuppressedByLocalContext(content, m) {
			continue
		}
		findings = append(findings, newFinding("secret", "jwt", "jwt_regex", m[0], m[1], false, 0.9, EvidenceContextual))
	}

	return findings
}

// phase25ContractVersion is the analysis contract version the engine sends to
// Phase 2.5 providers.
const phase25ContractVersion = "1"

// runPhase25 invokes the optional AI-sidecar provider with a privacy-bounded
// request containing only the ambiguous (non-hard) findings and their
// match-local context. Hard findings are never sent to the provider. Provider
// failures (timeout/unavailable) yield an empty response so the deterministic
// findings are preserved.
func (ce *ClassificationEngine) runPhase25(ctx context.Context, content string, findings []Finding, filePath string) AnalysisResponse {
	if ce.orchestrator == nil {
		return AnalysisResponse{Status: StatusAbstained}
	}

	ambiguous := make([]Finding, 0, len(findings))
	for _, f := range findings {
		if !f.HardEvidence {
			ambiguous = append(ambiguous, f)
		}
	}

	req := AnalysisRequest{
		ContractVersion:   phase25ContractVersion,
		RequestID:         uuid.NewString(),
		AmbiguousFindings: ambiguous,
		BoundedContext:    buildBoundedContext(content, ambiguous),
		ContentType:       filepath.Ext(filePath),
		Deadline:          defaultProviderDeadline,
	}

	resp, _ := ce.orchestrator.Execute(ctx, req)
	return resp
}

// buildBoundedContext concatenates the match-local windows around each
// ambiguous finding, bounded to a fixed maximum size so no unbounded document
// content ever reaches a provider.
func buildBoundedContext(content string, findings []Finding) string {
	const maxContextBytes = 2000

	var b strings.Builder
	for _, f := range findings {
		if f.StartOffset < 0 || f.StartOffset > len(content) || f.EndOffset < f.StartOffset {
			continue
		}
		length := f.EndOffset - f.StartOffset
		if f.EndOffset > len(content) {
			length = len(content) - f.StartOffset
		}
		local := ExtractMatchLocalContext(content, f.StartOffset, length, 0)
		if local == "" {
			continue
		}
		if b.Len() > 0 {
			b.WriteString("\n---\n")
		}
		b.WriteString(local)
		if b.Len() >= maxContextBytes {
			break
		}
	}
	return b.String()
}

// isSuppressedByLocalContext reports whether negative-context terms occur
// within the match-local window around the match at byte range idx. Only the
// bounded surrounding text is inspected, never the whole document.
func (ce *ClassificationEngine) isSuppressedByLocalContext(content string, idx []int) bool {
	local := ExtractMatchLocalContext(content, idx[0], idx[1]-idx[0], 0)
	return ce.isInNegativeContext(local)
}

// newFinding builds a Phase 2 deterministic finding.
func newFinding(fType, category, detector string, start, end int, hard bool, confidence float64, strength EvidenceStrength) Finding {
	return Finding{
		Type:             fType,
		Category:         category,
		Detector:         detector,
		SourcePhase:      "phase2",
		Confidence:       confidence,
		EvidenceStrength: strength,
		HardEvidence:     hard,
		StartOffset:      start,
		EndOffset:        end,
		Status:           StatusClassified,
	}
}

// phase2Keywords - keyword-based scoring
func (ce *ClassificationEngine) phase2Keywords(content string) float64 {
	score := float64(0)
	lowerContent := strings.ToLower(content)

	// Critical keywords (90+ = RESTRICTED immediately)
	criticalKeywords := []string{
		"cvv", "cvc", "cvv2", "cvc2", "card verification",
		"credit card", "debit card", "card number",
		"social security", "ssn", "national id", "passport number",
		"password", "secret key", "api key", "private key",
		"bank account", "routing number", "iban", "swift",
		"top secret", "classified", "highly confidential",
	}

	for _, kw := range criticalKeywords {
		if strings.Contains(lowerContent, kw) {
			score += 95 // Instant RESTRICTED level
		}
	}

	// High weight keywords (15 each)
	highWeightKeywords := []string{
		"confidential", "proprietary", "restricted", "internal use only",
		"salary", "payroll", "executive", "board meeting",
		"acquisition", "merger", "vulnerability", "exploit",
	}

	for _, kw := range highWeightKeywords {
		if strings.Contains(lowerContent, kw) {
			score += 15
		}
	}

	// Medium weight keywords (8 each)
	mediumWeightKeywords := []string{
		"invoice", "balance sheet", "customer", "contract", "nda", "employee",
		"financial", "medical", "performance review",
	}

	for _, kw := range mediumWeightKeywords {
		if strings.Contains(lowerContent, kw) {
			score += 8
		}
	}

	// Low weight keywords (3 each)
	lowWeightKeywords := []string{
		"memo", "internal", "note", "draft", "report",
	}

	for _, kw := range lowWeightKeywords {
		if strings.Contains(lowerContent, kw) {
			score += 3
		}
	}

	return score
}

// phase3ContextLogic - file type and context adjustments
func (ce *ClassificationEngine) phase3ContextLogic(filePath string, content string) float64 {
	adjustment := float64(0)
	ext := strings.ToLower(filepath.Ext(filePath))

	// CSV/XLSX bulk data
	if ext == ".csv" || ext == ".xlsx" {
		rowCount := strings.Count(content, "\n")
		if rowCount > 100 {
			adjustment += 30 // Bulk export = higher risk
		}
	}

	// Source code files - reduce PII but keep secrets
	if ext == ".py" || ext == ".js" || ext == ".go" || ext == ".cpp" || ext == ".java" {
		// Would apply heuristics here
		_ = adjustment
	}

	return adjustment
}

// phase4Decision - final classification decision
func (ce *ClassificationEngine) phase4Decision(score float64) EngineClassificationResult {
	// Clamp score
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	if score >= 90 {
		return EngineClassificationResult{
			Classification: string(ClassRestricted),
			Score:          score,
			Confidence:     95,
			Explanation:    "File contains classified/sensitive data",
			RiskLevel:      string(RiskCritical),
		}
	} else if score >= 50 {
		return EngineClassificationResult{
			Classification: string(ClassConfidential),
			Score:          score,
			Confidence:     85,
			Explanation:    "File contains restricted information",
			RiskLevel:      string(RiskMediumHigh),
		}
	} else if score >= 20 {
		return EngineClassificationResult{
			Classification: string(ClassInternal),
			Score:          score,
			Confidence:     75,
			Explanation:    "File for internal use only",
			RiskLevel:      string(RiskLow),
		}
	} else {
		return EngineClassificationResult{
			Classification: string(ClassPublic),
			Score:          score,
			Confidence:     100,
			Explanation:    "No sensitive data detected",
			RiskLevel:      string(RiskNone),
		}
	}
}

// CalculateRiskScore computes a 0-100 contextual risk score for an asset.
//
// Base score comes from the classification level, with adjustments for PII
// presence and a PUBLIC exposure level. The result is capped at 100.
func CalculateRiskScore(classification string, exposure string, hasPII bool) int {
	base := map[string]int{
		"PUBLIC":       0,
		"INTERNAL":     30,
		"CONFIDENTIAL": 60,
		"RESTRICTED":   80,
		"SECRET":       100,
	}

	score := base[strings.ToUpper(classification)]
	if hasPII {
		score += 10
	}
	if strings.ToUpper(exposure) == "PUBLIC" {
		score += 10
	}
	if score > 100 {
		score = 100
	}
	return score
}

// Helper methods

func (ce *ClassificationEngine) readFileContent(filePath string, maxSize int64) string {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return ""
	}

	if int64(len(data)) > maxSize {
		data = data[:maxSize]
	}

	// Only use text content
	return sanitizeContent(string(data))
}

func (ce *ClassificationEngine) isInNegativeContext(content string) bool {
	lowerContent := strings.ToLower(content)

	negativeContexts := []string{
		"example", "test", "sample", "fake", "mock", "dummy",
		"placeholder", "template", "demo", "tutorial", "guide",
		"documentation", "readme", "how to",
	}

	for _, nc := range negativeContexts {
		if strings.Contains(lowerContent, nc) {
			return true
		}
	}

	return false
}

func sanitizeContent(s string) string {
	// Filter out control characters but keep whitespace
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) && !unicode.IsSpace(r) {
			return -1
		}
		return r
	}, s)
}
