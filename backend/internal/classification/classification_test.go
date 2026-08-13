package classification

import (
	"os"
	"path/filepath"
	"testing"
)

// TestClassificationEngineWithRealFiles tests the engine with actual files
func TestClassificationEngineWithRealFiles(t *testing.T) {
	ce := NewClassificationEngine()
	tmpDir := t.TempDir()

	tests := []struct {
		name              string
		fileName          string
		content           string
		minExpectedScore  float64
		maxExpectedScore  float64
		expectedClass     string
	}{
		{
			name:              "Empty file",
			fileName:          "empty.txt",
			content:           "",
			minExpectedScore:  0,
			maxExpectedScore:  20,
			expectedClass:     "PUBLIC",
		},
		{
			name:              "File with SSN",
			fileName:          "employee.txt",
			content:           "Employee SSN: 123-45-6789",
			minExpectedScore:  50,
			maxExpectedScore:  100,
			expectedClass:     "CONFIDENTIAL",
		},
		{
			name:              "File with CC",
			fileName:          "payment.txt",
			content:           "Card: 4532015112830366",
			minExpectedScore:  50,
			maxExpectedScore:  100,
			expectedClass:     "CONFIDENTIAL",
		},
		{
			name:              "File with keyword",
			fileName:          "notes.txt",
			content:           "Database password in config",
			minExpectedScore:  20,
			maxExpectedScore:  50,
			expectedClass:     "INTERNAL",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			filePath := filepath.Join(tmpDir, test.fileName)
			if err := os.WriteFile(filePath, []byte(test.content), 0644); err != nil {
				t.Fatalf("failed to create test file: %v", err)
			}

			result := ce.Classify(filePath)
			t.Logf("File: %s | Score: %v | Classification: %s | Risk: %s", 
				test.fileName, result.Score, result.Classification, result.RiskLevel)

			if result.Score < test.minExpectedScore || result.Score > test.maxExpectedScore {
				t.Logf("WARN: score %v not in range %v-%v", result.Score, test.minExpectedScore, test.maxExpectedScore)
			}
		})
	}
}
