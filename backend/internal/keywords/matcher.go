package keywords

import (
	"regexp"
	"sort"
	"strings"
	"sync"
)

// KeywordMatch represents a keyword match result
type KeywordMatch struct {
	KeywordID      string `json:"keyword_id"`
	Keyword        string `json:"keyword"`
	MatchType      string `json:"match_type"`
	Classification string `json:"classification"`
	Priority       int    `json:"priority"`
	HardBlock      bool   `json:"hard_block"`
	MatchedText    string `json:"matched_text"`
	Position       int    `json:"position"`
}

// CompiledKeyword represents a pre-compiled keyword for matching
type CompiledKeyword struct {
	ID             string
	Keyword        string
	MatchType      string
	CaseSensitive  bool
	Classification string
	Priority       int
	HardBlock      bool
	Regex          *regexp.Regexp // For REGEX type
	LowerKeyword   string          // For case-insensitive matching
}

// Matcher handles keyword matching against content
type Matcher struct {
	mu       sync.RWMutex
	keywords []*CompiledKeyword
}

// NewMatcher creates a new keyword matcher
func NewMatcher() *Matcher {
	return &Matcher{
		keywords: make([]*CompiledKeyword, 0),
	}
}

// LoadKeywords loads and compiles keywords for matching
func (m *Matcher) LoadKeywords(keywords []*Keyword) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.keywords = make([]*CompiledKeyword, 0, len(keywords))

	for _, kw := range keywords {
		if !kw.Enabled {
			continue
		}

		compiled := &CompiledKeyword{
			ID:             kw.ID,
			Keyword:        kw.Keyword,
			MatchType:      kw.MatchType,
			CaseSensitive:  kw.CaseSensitive,
			Classification: kw.Classification,
			Priority:       kw.Priority,
			HardBlock:      kw.HardBlock,
		}

		// Pre-compute lowercase for case-insensitive matching
		if !kw.CaseSensitive {
			compiled.LowerKeyword = strings.ToLower(kw.Keyword)
		}

		// Compile regex patterns
		if kw.MatchType == "REGEX" {
			flags := ""
			if !kw.CaseSensitive {
				flags = "(?i)"
			}
			re, err := regexp.Compile(flags + kw.Keyword)
			if err == nil {
				compiled.Regex = re
			} else {
				// Skip invalid regex patterns
				continue
			}
		}

		m.keywords = append(m.keywords, compiled)
	}

	// Sort by priority (highest first)
	sort.Slice(m.keywords, func(i, j int) bool {
		return m.keywords[i].Priority > m.keywords[j].Priority
	})
}

// MatchContent matches content against all loaded keywords
func (m *Matcher) MatchContent(content string) []KeywordMatch {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var matches []KeywordMatch
	lowerContent := strings.ToLower(content)

	for _, kw := range m.keywords {
		switch kw.MatchType {
		case "EXACT":
			matches = append(matches, m.matchExact(content, lowerContent, kw)...)
		case "PARTIAL":
			matches = append(matches, m.matchPartial(content, lowerContent, kw)...)
		case "REGEX":
			matches = append(matches, m.matchRegex(content, kw)...)
		}
	}

	// Sort matches by priority (highest first)
	sort.Slice(matches, func(i, j int) bool {
		return matches[i].Priority > matches[j].Priority
	})

	return matches
}

// matchExact performs exact matching
func (m *Matcher) matchExact(content, lowerContent string, kw *CompiledKeyword) []KeywordMatch {
	var matches []KeywordMatch

	var searchContent, searchKeyword string
	if kw.CaseSensitive {
		searchContent = content
		searchKeyword = kw.Keyword
	} else {
		searchContent = lowerContent
		searchKeyword = kw.LowerKeyword
	}

	// Find exact word matches (with word boundaries)
	words := strings.Fields(searchContent)
	for i, word := range words {
		// Remove punctuation from word for comparison
		cleanWord := strings.Trim(word, ".,!?;:\"'()[]{}")
		if cleanWord == searchKeyword {
			matches = append(matches, KeywordMatch{
				KeywordID:      kw.ID,
				Keyword:        kw.Keyword,
				MatchType:      kw.MatchType,
				Classification: kw.Classification,
				Priority:       kw.Priority,
				HardBlock:      kw.HardBlock,
				MatchedText:    word,
				Position:       i,
			})
		}
	}

	return matches
}

// matchPartial performs partial/substring matching
func (m *Matcher) matchPartial(content, lowerContent string, kw *CompiledKeyword) []KeywordMatch {
	var matches []KeywordMatch

	var searchContent, searchKeyword string
	if kw.CaseSensitive {
		searchContent = content
		searchKeyword = kw.Keyword
	} else {
		searchContent = lowerContent
		searchKeyword = kw.LowerKeyword
	}

	pos := 0
	for {
		idx := strings.Index(searchContent[pos:], searchKeyword)
		if idx == -1 {
			break
		}

		actualPos := pos + idx
		matchedText := content[actualPos : actualPos+len(kw.Keyword)]

		matches = append(matches, KeywordMatch{
			KeywordID:      kw.ID,
			Keyword:        kw.Keyword,
			MatchType:      kw.MatchType,
			Classification: kw.Classification,
			Priority:       kw.Priority,
			HardBlock:      kw.HardBlock,
			MatchedText:    matchedText,
			Position:       actualPos,
		})

		pos = actualPos + len(searchKeyword)
		if pos >= len(searchContent) {
			break
		}
	}

	return matches
}

// matchRegex performs regex matching
func (m *Matcher) matchRegex(content string, kw *CompiledKeyword) []KeywordMatch {
	var matches []KeywordMatch

	if kw.Regex == nil {
		return matches
	}

	allMatches := kw.Regex.FindAllStringIndex(content, -1)
	for _, match := range allMatches {
		matches = append(matches, KeywordMatch{
			KeywordID:      kw.ID,
			Keyword:        kw.Keyword,
			MatchType:      kw.MatchType,
			Classification: kw.Classification,
			Priority:       kw.Priority,
			HardBlock:      kw.HardBlock,
			MatchedText:    content[match[0]:match[1]],
			Position:       match[0],
		})
	}

	return matches
}

// HasHardBlockMatch checks if content contains any hard block keywords
func (m *Matcher) HasHardBlockMatch(content string) (bool, *KeywordMatch) {
	matches := m.MatchContent(content)
	for _, match := range matches {
		if match.HardBlock {
			return true, &match
		}
	}
	return false, nil
}

// GetHighestClassification returns the highest classification from matches
func (m *Matcher) GetHighestClassification(matches []KeywordMatch) string {
	if len(matches) == 0 {
		return "PUBLIC"
	}

	classificationPriority := map[string]int{
		"PUBLIC":       0,
		"PRIVATE":      1,
		"CONFIDENTIAL": 2,
		"RESTRICTED":   3,
	}

	highest := "PUBLIC"
	for _, match := range matches {
		if classificationPriority[match.Classification] > classificationPriority[highest] {
			highest = match.Classification
		}
	}

	return highest
}

// ValidateRegex validates a regex pattern
func ValidateRegex(pattern string) error {
	_, err := regexp.Compile(pattern)
	return err
}
