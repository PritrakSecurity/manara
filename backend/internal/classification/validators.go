package classification

import (
	"regexp"
	"strconv"
	"strings"
)

// PatternValidators contains validation logic for various patterns
type PatternValidators struct {
	ccRegex      *regexp.Regexp
	ssnRegex     *regexp.Regexp
	nirRegex     *regexp.Regexp
	ibanRegex    *regexp.Regexp
	phoneUSRegex *regexp.Regexp
	phoneFRRegex *regexp.Regexp
}

// NewPatternValidators creates a new validator set
func NewPatternValidators() PatternValidators {
	return PatternValidators{
		ccRegex:      regexp.MustCompile(`\b(?:4[0-9]{12}|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b`),
		ssnRegex:     regexp.MustCompile(`(\d{3})-(\d{2})-(\d{4})`), // Simple pattern, validation done in ValidateSSN
		nirRegex:     regexp.MustCompile(`\b[12]\s?(?:0[1-9]|1[0-2])\s?(?:(?:19|20)\d{2}|\d{2})\s?(?:0[1-95]|[2-8]\d|9[0-5])\s?\d{3}\s?\d{3}(?:\s?\d{2})?\b`),
		ibanRegex:    regexp.MustCompile(`\b([A-Z]{2})\d{2}[\s]?(\d{4}[\s]?)*[A-Z0-9]{1,30}\b`),
		phoneUSRegex: regexp.MustCompile(`(?:\+?1[-.]?)?\(?[2-9][0-9]{2}\)?[-. ]?[2-9][0-9]{2}[-. ]?[0-9]{4}`),
		phoneFRRegex: regexp.MustCompile(`(?:\+?33|0)[67]\s?(?:[0-9]{2}\s?){4}`),
	}
}

// FindCreditCards finds valid credit card numbers in content
func (pv *PatternValidators) FindCreditCards(content string) []string {
	var validCards []string
	for _, m := range pv.FindCreditCardIndexes(content) {
		validCards = append(validCards, digitsOnly(content[m[0]:m[1]]))
	}
	return validCards
}

// FindCreditCardIndexes returns byte ranges of Luhn-valid credit card numbers.
func (pv *PatternValidators) FindCreditCardIndexes(content string) [][2]int {
	if pv.ccRegex == nil {
		return nil
	}
	matches := pv.ccRegex.FindAllStringIndex(content, -1)
	indexes := make([][2]int, 0, len(matches))
	for _, m := range matches {
		if pv.ValidateLuhn(digitsOnly(content[m[0]:m[1]])) {
			indexes = append(indexes, [2]int{m[0], m[1]})
		}
	}
	return indexes
}

// FindSSNs finds valid SSN patterns
func (pv *PatternValidators) FindSSNs(content string) []string {
	var validSSNs []string
	for _, m := range pv.FindSSNIndexes(content) {
		validSSNs = append(validSSNs, content[m[0]:m[1]])
	}
	return validSSNs
}

// FindSSNIndexes returns byte ranges of structurally valid SSN patterns.
func (pv *PatternValidators) FindSSNIndexes(content string) [][2]int {
	if pv.ssnRegex == nil {
		return nil
	}
	matches := pv.ssnRegex.FindAllStringIndex(content, -1)
	indexes := make([][2]int, 0, len(matches))
	for _, m := range matches {
		if pv.ValidateSSN(content[m[0]:m[1]]) {
			indexes = append(indexes, [2]int{m[0], m[1]})
		}
	}
	return indexes
}

// FindFrenchNIRs finds French NIR numbers
func (pv *PatternValidators) FindFrenchNIRs(content string) []string {
	var validNIRs []string
	for _, m := range pv.FindFrenchNIRIndexes(content) {
		validNIRs = append(validNIRs, content[m[0]:m[1]])
	}
	return validNIRs
}

// FindFrenchNIRIndexes returns byte ranges of structurally valid French NIRs.
func (pv *PatternValidators) FindFrenchNIRIndexes(content string) [][2]int {
	if pv.nirRegex == nil {
		return nil
	}
	matches := pv.nirRegex.FindAllStringIndex(content, -1)
	indexes := make([][2]int, 0, len(matches))
	for _, m := range matches {
		if pv.ValidateFrenchNIR(content[m[0]:m[1]]) {
			indexes = append(indexes, [2]int{m[0], m[1]})
		}
	}
	return indexes
}

// FindIBANs finds IBAN patterns
func (pv *PatternValidators) FindIBANs(content string) []string {
	var validIBANs []string
	for _, m := range pv.FindIBANIndexes(content) {
		validIBANs = append(validIBANs, content[m[0]:m[1]])
	}
	return validIBANs
}

// FindIBANIndexes returns byte ranges of structurally valid IBANs.
func (pv *PatternValidators) FindIBANIndexes(content string) [][2]int {
	if pv.ibanRegex == nil {
		return nil
	}
	matches := pv.ibanRegex.FindAllStringIndex(content, -1)
	indexes := make([][2]int, 0, len(matches))
	for _, m := range matches {
		if pv.ValidateIBAN(content[m[0]:m[1]]) {
			indexes = append(indexes, [2]int{m[0], m[1]})
		}
	}
	return indexes
}

// ValidateLuhn validates credit card using Luhn algorithm
func (pv *PatternValidators) ValidateLuhn(number string) bool {
	if len(number) < 13 || len(number) > 19 {
		return false
	}

	var sum int
	alternate := false

	// Process digits from right to left
	for i := len(number) - 1; i >= 0; i-- {
		n := int(number[i] - '0')

		if alternate {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}

		sum += n
		alternate = !alternate
	}

	return sum%10 == 0
}

// ValidateSSN validates Social Security Number format
func (pv *PatternValidators) ValidateSSN(ssn string) bool {
	if len(ssn) != 11 {
		return false
	}

	if ssn[3] != '-' || ssn[6] != '-' {
		return false
	}

	area := ssn[0:3]
	group := ssn[4:6]
	serial := ssn[7:11]

	// Invalid area: 000, 666, 9xx
	if area == "000" || area == "666" || area[0] == '9' {
		return false
	}

	// Invalid group: 00
	if group == "00" {
		return false
	}

	// Invalid serial: 0000
	if serial == "0000" {
		return false
	}

	return true
}

// ValidateFrenchNIR validates French NIR (Numéro d'Inscription Répertoire)
// Format: 13 or 15 digits with check digit: 97 - (number % 97)
func (pv *PatternValidators) ValidateFrenchNIR(nir string) bool {
	// Remove spaces
	cleaned := strings.ReplaceAll(nir, " ", "")

	if len(cleaned) < 13 || len(cleaned) > 15 {
		return false
	}

	// Extract digits only
	digits := strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, cleaned)

	if len(digits) < 13 {
		return false
	}

	// Gender must be 1 or 2
	if digits[0] != '1' && digits[0] != '2' {
		return false
	}

	// Month must be 01-12
	month, err := strconv.Atoi(digits[1:3])
	if err != nil || month < 1 || month > 12 {
		return false
	}

	// If has check digit, validate it
	if len(digits) == 15 {
		numberPart := digits[0:13]
		checkDigit := digits[13:15]

		num, err := strconv.ParseInt(numberPart, 10, 64)
		if err != nil {
			return false
		}

		expected := 97 - (num % 97)
		expectedStr := strconv.FormatInt(expected, 10)

		if expectedStr != checkDigit {
			return false
		}
	}

	return true
}

// ValidateIBAN validates International Bank Account Number
func (pv *PatternValidators) ValidateIBAN(iban string) bool {
	// Remove spaces
	iban = strings.ReplaceAll(iban, " ", "")
	iban = strings.ToUpper(iban)

	if len(iban) < 15 || len(iban) > 34 {
		return false
	}

	// Must start with 2-letter country code
	if !isAlpha(iban[0:2]) {
		return false
	}

	// Next 2 chars must be digits (check digits)
	if !isDigit(iban[2:4]) {
		return false
	}

	// Validate using mod-97
	return validateIBANMod97(iban)
}

// validateIBANMod97 validates IBAN using mod-97 algorithm
func validateIBANMod97(iban string) bool {
	// Move first 4 chars to end
	rearranged := iban[4:] + iban[0:4]

	// Replace letters with numbers (A=10, B=11, ... Z=35)
	var numStr strings.Builder
	for _, ch := range rearranged {
		if ch >= '0' && ch <= '9' {
			numStr.WriteRune(ch)
		} else if ch >= 'A' && ch <= 'Z' {
			numStr.WriteString(strconv.Itoa(int(ch-'A') + 10))
		} else {
			return false
		}
	}

	// Calculate mod 97
	return modCheck(numStr.String(), 97) == 1
}

// modCheck calculates mod of a large number string
func modCheck(numStr string, mod int) int {
	remainder := 0
	for _, ch := range numStr {
		digit := int(ch - '0')
		remainder = (remainder*10 + digit) % mod
	}
	return remainder
}

// Helper functions

// digitsOnly removes all non-digit characters from s.
func digitsOnly(s string) string {
	return strings.Map(func(r rune) rune {
		if r >= '0' && r <= '9' {
			return r
		}
		return -1
	}, s)
}

func isAlpha(s string) bool {
	for _, ch := range s {
		if !((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z')) {
			return false
		}
	}
	return true
}

func isDigit(s string) bool {
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return true
}
