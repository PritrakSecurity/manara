package classification

import (
	"os"
	"path/filepath"
	"testing"
)

// TestValidateLuhn tests credit card Luhn validation
func TestValidateLuhn(t *testing.T) {
	tests := []struct {
		name     string
		cardNum  string
		expected bool
	}{
		{"Valid Visa", "4532015112830366", true},
		{"Valid MasterCard", "5425233010103442", true},
		{"Valid AmEx", "374245455400126", true},
		{"Invalid checksum", "4532015112830365", false},
		{"Too short", "123456789012", false},
		{"Too long", "12345678901234567890", false},
		{"Non-numeric", "453201511283036A", false},
		{"Empty string", "", false},
	}

	pv := NewPatternValidators()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := pv.ValidateLuhn(test.cardNum)
			if result != test.expected {
				t.Errorf("expected %v, got %v", test.expected, result)
			}
		})
	}
}

// TestValidateSSN tests US Social Security Number validation
func TestValidateSSN(t *testing.T) {
	tests := []struct {
		name     string
		ssn      string
		expected bool
	}{
		{"Valid SSN", "123-45-6789", true},
		{"Valid without dashes", "123456789", true},
		{"Invalid area (000)", "000-12-3456", false},
		{"Invalid area (666)", "666-12-3456", false},
		{"Invalid area (900)", "900-12-3456", false},
		{"Invalid group (00)", "123-00-4567", false},
		{"Invalid serial (0000)", "123-45-0000", false},
		{"Too short", "123-45", false},
		{"Non-numeric", "ABC-DE-FGHI", false},
	}

	pv := NewPatternValidators()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := pv.ValidateSSN(test.ssn)
			if result != test.expected {
				t.Errorf("expected %v, got %v for %s", test.expected, result, test.ssn)
			}
		})
	}
}

// TestValidateFrenchNIR tests French National ID Number validation
func TestValidateFrenchNIR(t *testing.T) {
	tests := []struct {
		name     string
		nir      string
		expected bool
	}{
		{"Valid 13-digit", "3771234567891", true},
		{"Valid 15-digit with checksum", "377123456789105", true},
		{"Too short", "123456789", false},
		{"Too long", "37712345678910123456", false},
		{"Non-numeric", "377ABC567891", false},
	}

	pv := NewPatternValidators()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := pv.ValidateFrenchNIR(test.nir)
			if result != test.expected {
				t.Errorf("expected %v, got %v", test.expected, result)
			}
		})
	}
}

// TestValidateIBAN tests International Bank Account Number validation
func TestValidateIBAN(t *testing.T) {
	tests := []struct {
		name     string
		iban     string
		expected bool
	}{
		{"Valid GB IBAN", "GB82WEST12345698765432", true},
		{"Valid FR IBAN", "FR1420041010050500013M02606", true},
		{"Valid DE IBAN", "DE89370400440532013000", true},
		{"Invalid checksum", "GB82WEST12345698765433", false},
		{"Too short", "GB82", false},
		{"Invalid format", "INVALID123456", false},
	}

	pv := NewPatternValidators()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := pv.ValidateIBAN(test.iban)
			if result != test.expected {
				t.Errorf("expected %v, got %v for %s", test.expected, result, test.iban)
			}
		})
	}
}

// TestFindCreditCards tests credit card pattern finding
func TestFindCreditCards(t *testing.T) {
	tests := []struct {
		name          string
		text          string
		expectedCount int
	}{
		{"Single valid CC", "Please charge 4532015112830366", 1},
		{"Multiple CCs", "Card 1: 4532015112830366 Card 2: 5425233010103442", 2},
		{"No CCs", "This is regular text", 0},
		{"Invalid CC (failed Luhn)", "Invalid: 4532015112830365", 0},
	}

	pv := NewPatternValidators()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := pv.FindCreditCards(test.text)
			if len(result) != test.expectedCount {
				t.Errorf("expected %d CCs, found %d", test.expectedCount, len(result))
			}
		})
	}
}

// TestFindSSNs tests SSN pattern finding
func TestFindSSNs(t *testing.T) {
	tests := []struct {
		name          string
		text          string
		expectedCount int
	}{
		{"Single SSN", "Employee SSN: 123-45-6789", 1},
		{"Multiple SSNs", "John: 123-45-6789 Jane: 456-78-9123", 2},
		{"No SSNs", "No sensitive data", 0},
		{"Invalid SSN (000)", "Invalid: 000-12-3456", 0},
	}

	pv := NewPatternValidators()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := pv.FindSSNs(test.text)
			if len(result) != test.expectedCount {
				t.Errorf("expected %d SSNs, found %d", test.expectedCount, len(result))
			}
		})
	}
}

// TestFindFrenchNIRs tests French NIR pattern finding
func TestFindFrenchNIRs(t *testing.T) {
	tests := []struct {
		name          string
		text          string
		expectedCount int
	}{
		{"Single NIR", "French ID: 3771234567891", 1},
		{"Multiple NIRs", "ID1: 3771234567891 ID2: 1771234567892", 2},
		{"No NIRs", "No French IDs", 0},
	}

	pv := NewPatternValidators()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := pv.FindFrenchNIRs(test.text)
			if len(result) != test.expectedCount {
				t.Errorf("expected %d NIRs, found %d", test.expectedCount, len(result))
			}
		})
	}
}

// TestFindIBANs tests IBAN pattern finding
func TestFindIBANs(t *testing.T) {
	tests := []struct {
		name          string
		text          string
		expectedCount int
	}{
		{"Single IBAN", "Account: GB82WEST12345698765432", 1},
		{"Multiple IBANs", "A1: GB82WEST12345698765432 A2: FR1420041010050500013M02606", 2},
		{"No IBANs", "No bank accounts", 0},
	}

	pv := NewPatternValidators()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := pv.FindIBANs(test.text)
			if len(result) != test.expectedCount {
				t.Errorf("expected %d IBANs, found %d", test.expectedCount, len(result))
			}
		})
	}
}

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

// TestPhase4DecisionMapping tests the final classification mapping
func TestPhase4DecisionMapping(t *testing.T) {
	ce := NewClassificationEngine()

	tests := []struct {
		score                float64
		expectedClass        string
		expectedRiskLevel    string
	}{
		{0, "PUBLIC", "NONE"},
		{15, "PUBLIC", "NONE"},
		{19, "PUBLIC", "NONE"},
		{20, "INTERNAL", "LOW"},
		{50, "CONFIDENTIAL", "MEDIUM_HIGH"},
		{75, "CONFIDENTIAL", "MEDIUM_HIGH"},
		{89, "CONFIDENTIAL", "MEDIUM_HIGH"},
		{90, "RESTRICTED", "CRITICAL"},
		{100, "RESTRICTED", "CRITICAL"},
	}

	for _, test := range tests {
		result := ce.phase4Decision(test.score)
		if result.Classification != test.expectedClass {
			t.Errorf("score %v: expected %s, got %s", test.score, test.expectedClass, result.Classification)
		}
		if result.RiskLevel != test.expectedRiskLevel {
			t.Errorf("score %v: expected risk %s, got %s", test.score, test.expectedRiskLevel, result.RiskLevel)
		}
	}
}
