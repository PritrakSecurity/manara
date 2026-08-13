package classification

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strings"
)

// ContentScanner extracts text content from various file formats
type ContentScanner struct {
	maxFileSize int64 // Maximum file size to scan (bytes)
}

// NewContentScanner creates a new content scanner
func NewContentScanner() *ContentScanner {
	return &ContentScanner{
		maxFileSize: 50 * 1024 * 1024, // 50MB default limit
	}
}

// SetMaxFileSize sets the maximum file size to scan
func (s *ContentScanner) SetMaxFileSize(size int64) {
	s.maxFileSize = size
}

// ExtractText extracts text from file data based on file type
func (s *ContentScanner) ExtractText(data []byte, fileType string) (string, error) {
	if int64(len(data)) > s.maxFileSize {
		return "", fmt.Errorf("file exceeds maximum size limit of %d bytes", s.maxFileSize)
	}

	ext := strings.ToLower(fileType)
	if !strings.HasPrefix(ext, ".") {
		ext = "." + ext
	}

	switch ext {
	case ".txt", ".log", ".csv", ".json", ".xml", ".html", ".htm", ".md", ".yml", ".yaml", ".ini", ".cfg":
		return s.extractFromPlainText(data)
	case ".docx":
		return s.extractFromDOCX(data)
	case ".xlsx":
		return s.extractFromXLSX(data)
	case ".pptx":
		return s.extractFromPPTX(data)
	case ".pdf":
		return s.extractFromPDF(data)
	case ".rtf":
		return s.extractFromRTF(data)
	default:
		// Try as plain text for unknown types
		return s.extractFromPlainText(data)
	}
}

// extractFromPlainText extracts text from plain text files
func (s *ContentScanner) extractFromPlainText(data []byte) (string, error) {
	// Check if content is valid text
	text := string(data)

	// Remove null bytes that might indicate binary content
	text = strings.ReplaceAll(text, "\x00", "")

	// Basic validation - if too many non-printable characters, likely binary
	nonPrintable := 0
	for _, r := range text {
		if r < 32 && r != '\n' && r != '\r' && r != '\t' {
			nonPrintable++
		}
	}

	if len(text) > 0 && float64(nonPrintable)/float64(len(text)) > 0.1 {
		return "", fmt.Errorf("file appears to be binary content")
	}

	return text, nil
}

// extractFromDOCX extracts text from DOCX files
func (s *ContentScanner) extractFromDOCX(data []byte) (string, error) {
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return "", fmt.Errorf("failed to read DOCX: %w", err)
	}

	var text strings.Builder

	// Read document.xml (main content)
	for _, file := range reader.File {
		if file.Name == "word/document.xml" {
			rc, err := file.Open()
			if err != nil {
				continue
			}
			content, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				continue
			}

			extracted := extractTextFromXML(content)
			text.WriteString(extracted)
		}
	}

	return text.String(), nil
}

// extractFromXLSX extracts text from XLSX files
func (s *ContentScanner) extractFromXLSX(data []byte) (string, error) {
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return "", fmt.Errorf("failed to read XLSX: %w", err)
	}

	var text strings.Builder

	// Read shared strings first
	sharedStrings := make([]string, 0)
	for _, file := range reader.File {
		if file.Name == "xl/sharedStrings.xml" {
			rc, err := file.Open()
			if err != nil {
				continue
			}
			content, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				continue
			}

			sharedStrings = extractSharedStrings(content)
		}
	}

	// Read sheet data
	for _, file := range reader.File {
		if strings.HasPrefix(file.Name, "xl/worksheets/sheet") && strings.HasSuffix(file.Name, ".xml") {
			rc, err := file.Open()
			if err != nil {
				continue
			}
			content, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				continue
			}

			extracted := extractTextFromXLSXSheet(content, sharedStrings)
			text.WriteString(extracted)
			text.WriteString(" ")
		}
	}

	return text.String(), nil
}

// extractFromPPTX extracts text from PPTX files
func (s *ContentScanner) extractFromPPTX(data []byte) (string, error) {
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return "", fmt.Errorf("failed to read PPTX: %w", err)
	}

	var text strings.Builder

	for _, file := range reader.File {
		if strings.HasPrefix(file.Name, "ppt/slides/slide") && strings.HasSuffix(file.Name, ".xml") {
			rc, err := file.Open()
			if err != nil {
				continue
			}
			content, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				continue
			}

			extracted := extractTextFromXML(content)
			text.WriteString(extracted)
			text.WriteString(" ")
		}
	}

	return text.String(), nil
}

// extractFromPDF extracts text from PDF files (basic implementation)
func (s *ContentScanner) extractFromPDF(data []byte) (string, error) {
	// Basic PDF text extraction - looks for text between stream markers
	// For production, use a proper PDF library like pdfcpu or unipdf

	content := string(data)
	var text strings.Builder

	// Find text streams
	streamRegex := regexp.MustCompile(`stream\s*([\s\S]*?)endstream`)
	matches := streamRegex.FindAllStringSubmatch(content, -1)

	for _, match := range matches {
		if len(match) > 1 {
			// Extract readable text from stream
			extracted := extractReadableText(match[1])
			if extracted != "" {
				text.WriteString(extracted)
				text.WriteString(" ")
			}
		}
	}

	// Also look for text in Tj and TJ operators
	tjRegex := regexp.MustCompile(`\(([^)]+)\)\s*Tj`)
	tjMatches := tjRegex.FindAllStringSubmatch(content, -1)
	for _, match := range tjMatches {
		if len(match) > 1 {
			text.WriteString(match[1])
			text.WriteString(" ")
		}
	}

	result := text.String()
	if result == "" {
		return "", fmt.Errorf("could not extract text from PDF")
	}

	return result, nil
}

// extractFromRTF extracts text from RTF files
func (s *ContentScanner) extractFromRTF(data []byte) (string, error) {
	content := string(data)

	// Remove RTF control words and groups
	// This is a simplified implementation

	// Remove RTF header
	if !strings.HasPrefix(content, "{\\rtf") {
		return "", fmt.Errorf("invalid RTF format")
	}

	// Remove control words
	controlWord := regexp.MustCompile(`\\[a-z]+(-?\d+)?[ ]?`)
	text := controlWord.ReplaceAllString(content, "")

	// Remove braces
	text = strings.ReplaceAll(text, "{", "")
	text = strings.ReplaceAll(text, "}", "")

	// Clean up whitespace
	text = strings.TrimSpace(text)

	return text, nil
}

// Helper functions

// extractTextFromXML extracts text content from XML
func extractTextFromXML(data []byte) string {
	var text strings.Builder
	decoder := xml.NewDecoder(bytes.NewReader(data))

	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}

		switch t := token.(type) {
		case xml.CharData:
			content := strings.TrimSpace(string(t))
			if content != "" {
				text.WriteString(content)
				text.WriteString(" ")
			}
		}
	}

	return text.String()
}

// extractSharedStrings extracts shared strings from XLSX
func extractSharedStrings(data []byte) []string {
	var strings []string
	decoder := xml.NewDecoder(bytes.NewReader(data))

	inString := false
	var current string

	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}

		switch t := token.(type) {
		case xml.StartElement:
			if t.Name.Local == "t" {
				inString = true
				current = ""
			}
		case xml.CharData:
			if inString {
				current += string(t)
			}
		case xml.EndElement:
			if t.Name.Local == "t" && inString {
				strings = append(strings, current)
				inString = false
			}
		}
	}

	return strings
}

// extractTextFromXLSXSheet extracts text from XLSX sheet XML
func extractTextFromXLSXSheet(data []byte, sharedStrings []string) string {
	var text strings.Builder
	decoder := xml.NewDecoder(bytes.NewReader(data))

	inValue := false
	isSharedString := false
	var current string

	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}

		switch t := token.(type) {
		case xml.StartElement:
			if t.Name.Local == "c" {
				// Check if it's a shared string type
				isSharedString = false
				for _, attr := range t.Attr {
					if attr.Name.Local == "t" && attr.Value == "s" {
						isSharedString = true
						break
					}
				}
			}
			if t.Name.Local == "v" {
				inValue = true
				current = ""
			}
		case xml.CharData:
			if inValue {
				current += string(t)
			}
		case xml.EndElement:
			if t.Name.Local == "v" && inValue {
				if isSharedString {
					// Look up shared string
					idx := 0
					fmt.Sscanf(current, "%d", &idx)
					if idx >= 0 && idx < len(sharedStrings) {
						text.WriteString(sharedStrings[idx])
						text.WriteString(" ")
					}
				} else {
					text.WriteString(current)
					text.WriteString(" ")
				}
				inValue = false
			}
		}
	}

	return text.String()
}

// extractReadableText extracts readable ASCII text from content
func extractReadableText(content string) string {
	var text strings.Builder

	for _, r := range content {
		if (r >= 32 && r <= 126) || r == '\n' || r == '\t' {
			text.WriteRune(r)
		} else if r == '\r' {
			// Skip carriage returns
		} else {
			// Add space for other characters if we have content
			if text.Len() > 0 {
				text.WriteRune(' ')
			}
		}
	}

	return strings.TrimSpace(text.String())
}

// GetMimeType returns the MIME type for a file extension
func GetMimeType(ext string) string {
	ext = strings.ToLower(ext)
	if !strings.HasPrefix(ext, ".") {
		ext = "." + ext
	}

	mimeTypes := map[string]string{
		".txt":  "text/plain",
		".pdf":  "application/pdf",
		".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
		".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
		".doc":  "application/msword",
		".xls":  "application/vnd.ms-excel",
		".ppt":  "application/vnd.ms-powerpoint",
		".rtf":  "application/rtf",
		".html": "text/html",
		".htm":  "text/html",
		".xml":  "application/xml",
		".json": "application/json",
		".csv":  "text/csv",
		".md":   "text/markdown",
	}

	if mime, ok := mimeTypes[ext]; ok {
		return mime
	}
	return "application/octet-stream"
}

// GetFileTypeFromPath extracts file extension from path
func GetFileTypeFromPath(path string) string {
	return filepath.Ext(path)
}
