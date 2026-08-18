package classification

import (
	"unicode/utf8"
)

const (
	// defaultMatchContextSize is the default window size in runes when no
	// explicit size is provided.
	defaultMatchContextSize = 250
	// maxMatchContextSize is the strict upper bound for a context window.
	maxMatchContextSize = 500
)

// ExtractMatchLocalContext returns a bounded window of text centered on the
// match at byte range [offset, offset+length). The window spans at most
// contextSize runes (default 250 when contextSize <= 0); configurations larger
// than maxMatchContextSize are rejected with an empty result. The returned
// text is always valid UTF-8 and never splits a multi-byte code point. Matches
// at the very start or end of the input are handled without panicking.
func ExtractMatchLocalContext(text string, offset int, length int, contextSize int) string {
	if contextSize > maxMatchContextSize {
		return ""
	}
	if contextSize <= 0 {
		contextSize = defaultMatchContextSize
	}
	if offset < 0 || offset > len(text) || length < 0 {
		return ""
	}
	end := offset + length
	if end > len(text) {
		end = len(text)
	}
	if end < offset {
		return ""
	}

	runes := []rune(text)
	start := utf8.RuneCountInString(text[:offset])
	stop := utf8.RuneCountInString(text[:end])

	before := contextSize / 2
	after := contextSize - before

	winStart := start - before
	if winStart < 0 {
		winStart = 0
	}
	winEnd := stop + after
	if winEnd > len(runes) {
		winEnd = len(runes)
	}
	return string(runes[winStart:winEnd])
}
