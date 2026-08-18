package classification

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func key(n int, ch byte) string {
	return "api_key=" + strings.Repeat(string(ch), n)
}

// TestContextExampleBesideFakeCredential verifies a negative-context term
// directly adjacent to a credential suppresses it.
func TestContextExampleBesideFakeCredential(t *testing.T) {
	ce := NewClassificationEngine()
	content := "example " + key(40, 'a')

	if score := ce.phase2Secrets(content); score != 20 {
		t.Fatalf("expected suppressed secret (score 20 from api_key keyword only), got %v", score)
	}
}

// TestContextExampleElsewhereDoesNotSuppress verifies a negative-context term
// far away from a real credential no longer suppresses it.
func TestContextExampleElsewhereDoesNotSuppress(t *testing.T) {
	ce := NewClassificationEngine()
	prefix := "example of a document that explains the onboarding flow\n\n"
	filler := strings.Repeat("plain text filler content\n", 20)
	suffix := key(40, 'b')
	content := prefix + filler + suffix

	if score := ce.phase2Secrets(content); score != 90 {
		t.Fatalf("expected real secret scored (90 = 70 regex + 20 keyword), got %v", score)
	}

	idx := strings.Index(content, suffix)
	if local := ExtractMatchLocalContext(content, idx, len(suffix), 0); strings.Contains(local, "example") {
		t.Fatalf("distant negative-context term leaked into match-local window: %q", local)
	}
}

// TestContextMultipleSecrets verifies each secret is judged by its own
// surrounding context.
func TestContextMultipleSecrets(t *testing.T) {
	ce := NewClassificationEngine()
	bad := "example " + key(40, 'c')
	filler := strings.Repeat("safe filler text here\n", 10)
	good := key(40, 'd')
	content := bad + "\n" + filler + good

	badIdx := strings.Index(content, bad)
	goodIdx := strings.Index(content, good)

	if local := ExtractMatchLocalContext(content, badIdx, len(bad), 0); !strings.Contains(local, "example") {
		t.Fatalf("bad secret window should contain its adjacent negative context: %q", local)
	}
	if local := ExtractMatchLocalContext(content, goodIdx, len(good), 0); strings.Contains(local, "example") {
		t.Fatalf("good secret window leaked distant negative context: %q", local)
	}

	findings := ce.collectPhase2Findings(content)
	var secretFindings []Finding
	for _, f := range findings {
		if f.Category == "api_key" {
			secretFindings = append(secretFindings, f)
		}
	}
	if len(secretFindings) != 1 {
		t.Fatalf("expected exactly 1 api_key finding (the unsuppressed one), got %d", len(secretFindings))
	}
	if secretFindings[0].StartOffset != goodIdx {
		t.Fatalf("expected finding at the good secret offset %d, got %d", goodIdx, secretFindings[0].StartOffset)
	}
	if secretFindings[0].HardEvidence {
		t.Fatalf("regex-based secret must not be hard evidence: %+v", secretFindings[0])
	}
}

// TestContextUnicode verifies the window never splits a multi-byte character.
func TestContextUnicode(t *testing.T) {
	content := "héllo wörld — " + key(40, 'a') + " 🚀 émoji"
	idx := strings.Index(content, "api_key")

	local := ExtractMatchLocalContext(content, idx, len(key(40, 'a')), 0)

	if !utf8.ValidString(local) {
		t.Fatalf("context is not valid UTF-8: %q", local)
	}
	if strings.ContainsRune(local, utf8.RuneError) {
		t.Fatalf("context contains replacement runes, multi-byte chars were split: %q", local)
	}
	if !strings.Contains(local, "api_key") || !strings.Contains(local, "🚀") {
		t.Fatalf("context lost the match or its surroundings: %q", local)
	}

	ce := NewClassificationEngine()
	if score := ce.phase2Secrets(content); score != 90 {
		t.Fatalf("expected unsuppressed unicode-adjacent secret (90), got %v", score)
	}
}

// TestContextAtFileBoundaries verifies matches at the start/end of input are
// handled without panicking.
func TestContextAtFileBoundaries(t *testing.T) {
	atStart := key(40, 'a') + " trailing content"
	if ctx := ExtractMatchLocalContext(atStart, 0, len(key(40, 'a')), 0); !strings.HasPrefix(ctx, "api_key=") {
		t.Fatalf("expected window to start with the match, got %q", ctx)
	}

	atEnd := "leading content " + key(40, 'b')
	idx := strings.Index(atEnd, "api_key")
	if ctx := ExtractMatchLocalContext(atEnd, idx, len(atEnd)-idx, 0); !strings.Contains(ctx, "api_key=") {
		t.Fatalf("expected window to contain the end-of-file match, got %q", ctx)
	}
}

// TestContextInvalidInput verifies invalid offsets and configurations are
// rejected without panicking.
func TestContextInvalidInput(t *testing.T) {
	tests := []struct {
		name        string
		offset      int
		length      int
		contextSize int
	}{
		{name: "negative offset", offset: -1, length: 5, contextSize: 0},
		{name: "offset past end", offset: 999, length: 5, contextSize: 0},
		{name: "negative length", offset: 0, length: -1, contextSize: 0},
		{name: "context size over max", offset: 0, length: 0, contextSize: 600},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ExtractMatchLocalContext("hello", tt.offset, tt.length, tt.contextSize); got != "" {
				t.Fatalf("expected empty context for invalid input, got %q", got)
			}
		})
	}

	if got := ExtractMatchLocalContext("hello", 5, 5, 0); got != "hello" {
		t.Fatalf("degenerate offset at end of input should not panic, got %q", got)
	}
}
