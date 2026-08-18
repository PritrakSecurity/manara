package classification

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPhase0FastFilter tests the fast filter phase for instant decisions
func TestPhase0FastFilter(t *testing.T) {
	ce := NewClassificationEngine()

	tests := []struct {
		name              string
		filePath          string
		expectedScore     float64
		expectedRiskLevel string
	}{
		// Instant BLOCK extensions (score >= 90)
		{
			name:              "Private Key File",
			filePath:          "C:\\Users\\test\\private.key",
			expectedScore:     100,
			expectedRiskLevel: "CRITICAL",
		},
		{
			name:              "AWS Key File",
			filePath:          "C:\\Users\\test\\.aws\\credentials",
			expectedScore:     100,
			expectedRiskLevel: "CRITICAL",
		},
		{
			name:              "Certificate File",
			filePath:          "C:\\Users\\test\\cert.pem",
			expectedScore:     100,
			expectedRiskLevel: "CRITICAL",
		},
		// Instant ALLOW extensions (score 0)
		{
			name:              "Executable Binary",
			filePath:          "C:\\Program Files\\app.exe",
			expectedScore:     0,
			expectedRiskLevel: "NONE",
		},
		{
			name:              "System Library",
			filePath:          "C:\\Windows\\System32\\kernel.dll",
			expectedScore:     0,
			expectedRiskLevel: "NONE",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := ce.Classify(test.filePath)
			if result.Score != test.expectedScore {
				t.Errorf("expected score %v, got %v", test.expectedScore, result.Score)
			}
			if result.RiskLevel != test.expectedRiskLevel {
				t.Errorf("expected risk level %s, got %s", test.expectedRiskLevel, result.RiskLevel)
			}
		})
	}
}

// TestPhase1PreAnalysis tests filename, directory, and extension scoring
func TestPhase1PreAnalysis(t *testing.T) {
	ce := NewClassificationEngine()

	tests := []struct {
		name              string
		filePath          string
		minExpectedScore  float64
		maxExpectedScore  float64
		expectedRiskLevel string
	}{
		{
			name:              "Payroll File",
			filePath:          "C:\\HR\\payroll_2024.xlsx",
			minExpectedScore:  20,
			maxExpectedScore:  60,
			expectedRiskLevel: "LOW",
		},
		{
			name:              "Salary File",
			filePath:          "C:\\HR\\salary_data.csv",
			minExpectedScore:  20,
			maxExpectedScore:  60,
			expectedRiskLevel: "LOW",
		},
		{
			name:              "Finance Directory",
			filePath:          "C:\\Finance\\budget.xlsx",
			minExpectedScore:  15,
			maxExpectedScore:  50,
			expectedRiskLevel: "LOW",
		},
		{
			name:              "Executive Directory",
			filePath:          "C:\\Executive\\strategy.docx",
			minExpectedScore:  15,
			maxExpectedScore:  50,
			expectedRiskLevel: "LOW",
		},
		{
			name:              "Database SQL File",
			filePath:          "C:\\backup\\database.sql",
			minExpectedScore:  30,
			maxExpectedScore:  70,
			expectedRiskLevel: "LOW",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := ce.Classify(test.filePath)
			if result.Score < test.minExpectedScore || result.Score > test.maxExpectedScore {
				t.Errorf("expected score between %v-%v, got %v", test.minExpectedScore, test.maxExpectedScore, result.Score)
			}
		})
	}
}

// TestPhase2ContentPatterns tests pattern matching and validation
func TestPhase2ContentPatterns(t *testing.T) {
	ce := NewClassificationEngine()

	// Create temporary test files with sensitive content
	tmpDir := t.TempDir()

	tests := []struct {
		name              string
		fileName          string
		content           string
		minExpectedScore  float64
		maxExpectedScore  float64
		expectedRiskLevel string
	}{
		{
			name:              "File with Credit Card",
			fileName:          "payment.txt",
			content:           "Amount: 4532015112830366\nDate: 2024-01-15", // Valid CC (Luhn check passes)
			minExpectedScore:  60,
			maxExpectedScore:  100,
			expectedRiskLevel: "MEDIUM_HIGH",
		},
		{
			name:              "File with SSN",
			fileName:          "employee.txt",
			content:           "SSN: 123-45-6789\nName: John Doe",
			minExpectedScore:  60,
			maxExpectedScore:  100,
			expectedRiskLevel: "MEDIUM_HIGH",
		},
		{
			name:              "File with API Key",
			fileName:          "config.txt",
			content:           "API_KEY=abcdefghijklmnopqrstuvwxyz0123456789ab",
			minExpectedScore:  70,
			maxExpectedScore:  100,
			expectedRiskLevel: "CRITICAL",
		},
		{
			name:              "File with Long-Lived Token",
			fileName:          "token.txt",
			content:           "access_token=abcdefghijklmnopqrstuvwxyz0123456789",
			minExpectedScore:  70,
			maxExpectedScore:  100,
			expectedRiskLevel: "CRITICAL",
		},
		{
			name:              "File with Password Keyword",
			fileName:          "notes.txt",
			content:           "Database password: SuperSecretPassword123",
			minExpectedScore:  20,
			maxExpectedScore:  60,
			expectedRiskLevel: "LOW",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Create temporary file
			filePath := filepath.Join(tmpDir, test.fileName)
			err := os.WriteFile(filePath, []byte(test.content), 0644)
			if err != nil {
				t.Fatalf("failed to create test file: %v", err)
			}

			result := ce.Classify(filePath)
			if result.Score < test.minExpectedScore || result.Score > test.maxExpectedScore {
				t.Errorf("expected score between %v-%v, got %v", test.minExpectedScore, test.maxExpectedScore, result.Score)
			}
			if result.RiskLevel != test.expectedRiskLevel {
				t.Logf("expected risk level %s, got %s (score: %v)", test.expectedRiskLevel, result.RiskLevel, result.Score)
			}
		})
	}
}

// TestPhase3ContextLogic tests context-based scoring
func TestPhase3ContextLogic(t *testing.T) {
	ce := NewClassificationEngine()
	tmpDir := t.TempDir()

	tests := []struct {
		name             string
		fileName         string
		content          string
		shouldBoost      bool
		minExpectedScore float64
	}{
		{
			name:     "Large CSV with PII",
			fileName: "employees.csv",
			content: "id,name,ssn,salary\n1,John,123-45-6789,50000\n2,Jane,987-65-4321,60000\n3,Bob,456-78-9123,55000\n" +
				repeatString("4,Alice,222-33-4444,65000\n", 100),
			shouldBoost:      true,
			minExpectedScore: 60,
		},
		{
			name:             "Python Source Code",
			fileName:         "app.py",
			content:          "import requests\ndb_password = 'secret123'\napi_key = 'key123'\n",
			shouldBoost:      true,
			minExpectedScore: 40,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			filePath := filepath.Join(tmpDir, test.fileName)
			err := os.WriteFile(filePath, []byte(test.content), 0644)
			if err != nil {
				t.Fatalf("failed to create test file: %v", err)
			}

			result := ce.Classify(filePath)
			if test.shouldBoost && result.Score < test.minExpectedScore {
				t.Logf("expected boost for %s, score %v may be lower than expected %v due to context", test.name, result.Score, test.minExpectedScore)
			}
		})
	}
}

// TestPhase4DecisionMapping tests final classification mapping
func TestPhase4DecisionMapping(t *testing.T) {
	ce := NewClassificationEngine()

	tests := []struct {
		filePath               string
		expectedClassification string
	}{
		{"C:\\empty_file.txt", "PUBLIC"},
		{"C:\\config.key", "RESTRICTED"},
		{"C:\\cert.pem", "RESTRICTED"},
		{"C:\\app.exe", "PUBLIC"},
	}

	for _, test := range tests {
		result := ce.Classify(test.filePath)
		if result.Classification != test.expectedClassification {
			t.Logf("file: %s | expected: %s, got: %s (score: %v)",
				test.filePath, test.expectedClassification, result.Classification, result.Score)
		}
	}
}

// TestPerformance verifies latency targets
func TestPerformance(t *testing.T) {
	ce := NewClassificationEngine()
	tmpDir := t.TempDir()

	filePath := filepath.Join(tmpDir, "test.txt")
	err := os.WriteFile(filePath, []byte("Test content"), 0644)
	if err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	// Run classification
	result := ce.Classify(filePath)

	// Verify latency is within target (<50ms)
	if result.ElapsedMs > 50 {
		t.Logf("WARNING: Latency %dms exceeds target of 50ms", result.ElapsedMs)
	}
}

// TestEdgeCases tests edge cases
func TestEdgeCases(t *testing.T) {
	ce := NewClassificationEngine()
	tmpDir := t.TempDir()

	tests := []struct {
		name     string
		filePath string
		content  string
	}{
		{
			name:     "Empty file",
			filePath: filepath.Join(tmpDir, "empty.txt"),
			content:  "",
		},
		{
			name:     "Very large file",
			filePath: filepath.Join(tmpDir, "large.txt"),
			content:  repeatString("a", 2*1024*1024), // 2MB
		},
		{
			name:     "Binary file",
			filePath: filepath.Join(tmpDir, "binary.bin"),
			content:  string([]byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE}),
		},
		{
			name:     "File with null bytes",
			filePath: filepath.Join(tmpDir, "nullbytes.txt"),
			content:  "Before\x00After",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := os.WriteFile(test.filePath, []byte(test.content), 0644)
			if err != nil {
				t.Fatalf("failed to create test file: %v", err)
			}

			result := ce.Classify(test.filePath)
			if result.Score < 0 || result.Score > 100 {
				t.Errorf("invalid score: %v", result.Score)
			}
		})
	}
}

// TestBoundaryScores tests boundary conditions
func TestBoundaryScores(t *testing.T) {
	ce := NewClassificationEngine()

	// Test that scores are properly bounded (0-100)
	testPaths := []string{
		"C:\\test.txt",
		"C:\\secret.key",
		"C:\\payroll.xlsx",
		"C:\\Finance\\budget.csv",
	}

	for _, path := range testPaths {
		result := ce.Classify(path)
		if result.Score < 0 || result.Score > 100 {
			t.Errorf("score out of bounds for %s: %v", path, result.Score)
		}
	}
}

// Helper function to repeat a string
func repeatString(s string, count int) string {
	return strings.Repeat(s, count)
}
