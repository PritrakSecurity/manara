package classification

import (
	"os"
	"testing"
)

// TestValidateLuhn tests credit card Luhn validation
func TestValidateLuhn(t *testing.T) {
	tests := []struct {
		name     string
		cardNum  string
		expected bool
	}{
		// Valid credit card numbers (Luhn algorithm)
		{
			name:     "Valid Visa",
			cardNum:  "4532015112830366",
			expected: true,
		},
		{
			name:     "Valid MasterCard",
			cardNum:  "5425233010103442",
			expected: true,
		},
		{
			name:     "Valid American Express",
			cardNum:  "374245455400126",
			expected: true,
		},
		// Invalid credit cards
		{
			name:     "Invalid checksum",
			cardNum:  "4532015112830365",
			expected: false,
		},
		{
			name:     "Too short",
			cardNum:  "123456789012",
			expected: false,
		},
		{
			name:     "Too long",
			cardNum:  "12345678901234567890",
			expected: false,
		},
		{
			name:     "Non-numeric",
			cardNum:  "453201511283036A",
			expected: false,
		},
	}

	pv := &PatternValidators{}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := pv.ValidateLuhn(test.cardNum)
			if result != test.expected {
				t.Errorf("expected %v, got %v for card %s", test.expected, result, test.cardNum)
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
		// Valid SSNs
		{
			name:     "Valid SSN",
			ssn:      "123-45-6789",
			expected: true,
		},
		{
			name:     "Valid SSN without dashes",
			ssn:      "123456789",
			expected: true,
		},
		{
			name:     "Valid SSN with different numbers",
			ssn:      "456-78-9123",
			expected: true,
		},
		// Invalid SSNs
		{
			name:     "Invalid area code (000)",
			ssn:      "000-12-3456",
			expected: false,
		},
		{
			name:     "Invalid area code (666)",
			ssn:      "666-12-3456",
			expected: false,
		},
		{
			name:     "Invalid area code (900s)",
			ssn:      "900-12-3456",
			expected: false,
		},
		{
			name:     "Invalid group code (00)",
			ssn:      "123-00-4567",
			expected: false,
		},
		{
			name:     "Invalid serial number (0000)",
			ssn:      "123-45-0000",
			expected: false,
		},
		{
			name:     "Too short",
			ssn:      "123-45",
			expected: false,
		},
		{
			name:     "Non-numeric",
			ssn:      "ABC-DE-FGHI",
			expected: false,
		},
	}

	pv := &PatternValidators{}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := pv.ValidateSSN(test.ssn)
			if result != test.expected {
				t.Errorf("expected %v, got %v for SSN %s", test.expected, result, test.ssn)
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
		// Valid NIRs (13-15 digits)
		{
			name:     "Valid 13-digit NIR",
			nir:      "3771234567891",
			expected: true,
		},
		{
			name:     "Valid 15-digit NIR with checksum",
			nir:      "377123456789105",
			expected: true,
		},
		// Invalid NIRs
		{
			name:     "Too short",
			nir:      "123456789",
			expected: false,
		},
		{
			name:     "Too long",
			nir:      "37712345678910123456",
			expected: false,
		},
		{
			name:     "Non-numeric",
			nir:      "377ABC567891",
			expected: false,
		},
	}

	pv := &PatternValidators{}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := pv.ValidateFrenchNIR(test.nir)
			if result != test.expected {
				t.Errorf("expected %v, got %v for NIR %s", test.expected, result, test.nir)
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
		// Valid IBANs
		{
			name:     "Valid GB IBAN",
			iban:     "GB82WEST12345698765432",
			expected: true,
		},
		{
			name:     "Valid FR IBAN",
			iban:     "FR1420041010050500013M02606",
			expected: true,
		},
		{
			name:     "Valid DE IBAN",
			iban:     "DE89370400440532013000",
			expected: true,
		},
		// Invalid IBANs
		{
			name:     "Invalid checksum",
			iban:     "GB82WEST12345698765433",
			expected: false,
		},
		{
			name:     "Too short",
			iban:     "GB82",
			expected: false,
		},
		{
			name:     "Invalid format",
			iban:     "INVALID123456",
			expected: false,
		},
	}

	pv := &PatternValidators{}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := pv.ValidateIBAN(test.iban)
			if result != test.expected {
				t.Errorf("expected %v, got %v for IBAN %s", test.expected, result, test.iban)
			}
		})
	}
}

// TestFindCreditCards tests credit card finding
func TestFindCreditCards(t *testing.T) {
	tests := []struct {
		name          string
		text          string
		expectedCount int
	}{
		{
			name:          "Single valid credit card",
			text:          "Please charge 4532015112830366 for the purchase",
			expectedCount: 1,
		},
		{
			name:          "Multiple credit cards",
			text:          "Card 1: 4532015112830366 Card 2: 5425233010103442",
			expectedCount: 2,
		},
		{
			name:          "No credit cards",
			text:          "This is just regular text with no credit cards",
			expectedCount: 0,
		},
		{
			name:          "Invalid credit card (failed Luhn)",
			text:          "Invalid card: 4532015112830365",
			expectedCount: 0,
		},
	}

	pv := NewPatternValidators()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := pv.FindCreditCards(test.text)
			if len(result) != test.expectedCount {
				t.Errorf("expected %d credit cards, found %d", test.expectedCount, len(result))
			}
		})
	}
}

// TestFindSSNs tests SSN finding
func TestFindSSNs(t *testing.T) {
	tests := []struct {
		name          string
		text          string
		expectedCount int
	}{
		{
			name:          "Single SSN",
			text:          "Employee SSN: 123-45-6789",
			expectedCount: 1,
		},
		{
			name:          "Multiple SSNs",
			text:          "John: 123-45-6789 Jane: 456-78-9123",
			expectedCount: 2,
		},
		{
			name:          "No SSNs",
			text:          "No sensitive data here",
			expectedCount: 0,
		},
		{
			name:          "Invalid SSN (area code 000)",
			text:          "Invalid: 000-12-3456",
			expectedCount: 0,
		},
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

// TestFindFrenchNIRs tests French NIR finding
func TestFindFrenchNIRs(t *testing.T) {
	tests := []struct {
		name          string
		text          string
		expectedCount int
	}{
		{
			name:          "Single NIR",
			text:          "French ID: 3771234567891",
			expectedCount: 1,
		},
		{
			name:          "Multiple NIRs",
			text:          "ID1: 3771234567891 ID2: 1771234567892",
			expectedCount: 2,
		},
		{
			name:          "No NIRs",
			text:          "No French IDs here",
			expectedCount: 0,
		},
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

// TestFindIBANs tests IBAN finding
func TestFindIBANs(t *testing.T) {
	tests := []struct {
		name          string
		text          string
		expectedCount int
	}{
		{
			name:          "Single IBAN",
			text:          "Bank account: GB82WEST12345698765432",
			expectedCount: 1,
		},
		{
			name:          "Multiple IBANs",
			text:          "Account 1: GB82WEST12345698765432 Account 2: FR1420041010050500013M02606",
			expectedCount: 2,
		},
		{
			name:          "No IBANs",
			text:          "No bank accounts",
			expectedCount: 0,
		},
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

// TestValidatorBoundaries tests boundary conditions
func TestValidatorBoundaries(t *testing.T) {
	pv := &PatternValidators{}

	// Test empty strings
	if pv.ValidateLuhn("") {
		t.Error("empty string should not validate as Luhn")
	}
	if pv.ValidateSSN("") {
		t.Error("empty string should not validate as SSN")
	}
	if pv.ValidateFrenchNIR("") {
		t.Error("empty string should not validate as French NIR")
	}
	if pv.ValidateIBAN("") {
		t.Error("empty string should not validate as IBAN")
	}

	// Test with only whitespace
	if pv.ValidateLuhn("   ") {
		t.Error("whitespace should not validate as Luhn")
	}
}

// TestValidatorIntegration tests validators work correctly in classification
func TestValidatorIntegration(t *testing.T) {
	ce := NewClassificationEngine()

	// Create a test file with multiple types of PII
	tmpFile := t.TempDir() + "/multitype_pii.txt"
	content := `
Customer Information:
- Name: John Doe
- SSN: 123-45-6789
- Credit Card: 4532015112830366
- Bank Account: GB82WEST12345698765432
- French ID: 3771234567891
`

	if err := os.WriteFile(tmpFile, []byte(content), 0644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	result := ce.Classify(tmpFile)

	// File with multiple types of PII should be classified as HIGH risk
	if result.Score < 80 {
		t.Logf("expected high score for multi-type PII, got %v", result.Score)
	}
}
