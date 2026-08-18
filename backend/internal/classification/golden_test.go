package classification

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

// corpusCase mirrors one line of corpus.jsonl (testdata/corpus).
type corpusCase struct {
	ID                     string            `json:"id"`
	ContentType            string            `json:"content_type"`
	Content                string            `json:"content"`
	ExpectedClassification string            `json:"expected_classification"`
	ExpectedHardFindings   []expectedFinding `json:"expected_hard_findings"`
}

// expectedFinding is the comparable, privacy-safe subset of a hard finding.
type expectedFinding struct {
	Type             string `json:"type"`
	Detector         string `json:"detector"`
	EvidenceStrength string `json:"evidence_strength"`
}

// TestGoldenCorpus runs the deterministic engine (all optional providers
// disabled) against the synthetic corpus and asserts the classification and
// hard findings match the recorded baseline. This pins the current behavior:
// if a future change shifts it, this test fails.
func TestGoldenCorpus(t *testing.T) {
	f, err := os.Open(filepath.Join("testdata", "corpus", "corpus.jsonl"))
	if err != nil {
		t.Fatalf("failed to open corpus: %v", err)
	}
	defer f.Close()

	ce := NewClassificationEngine()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	line := 0
	for sc.Scan() {
		line++
		raw := sc.Text()
		if raw == "" {
			continue
		}
		var tc corpusCase
		if err := json.Unmarshal([]byte(raw), &tc); err != nil {
			t.Fatalf("corpus line %d invalid: %v", line, err)
		}

		t.Run(tc.ID, func(t *testing.T) {
			path := filepath.Join("corpus", tc.ID+".txt")
			result := ce.ClassifyWithContent(path, tc.Content, int64(len(tc.Content)))

			if result.Classification != tc.ExpectedClassification {
				t.Errorf("%s: classification = %q, want %q (score %v)", tc.ID, result.Classification, tc.ExpectedClassification, result.Score)
			}

			got := hardFindingSummaries(result.Findings)
			want := make([]expectedFinding, 0, len(tc.ExpectedHardFindings))
			want = append(want, tc.ExpectedHardFindings...)
			sort.Slice(got, func(i, j int) bool { return findingSortKey(got[i]) < findingSortKey(got[j]) })
			sort.Slice(want, func(i, j int) bool { return findingSortKey(want[i]) < findingSortKey(want[j]) })
			if !reflect.DeepEqual(got, want) {
				t.Errorf("%s: hard findings = %+v, want %+v", tc.ID, got, want)
			}
		})
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("failed to read corpus: %v", err)
	}
}

// hardFindingSummaries projects only the hard findings to their comparable,
// privacy-safe form.
func hardFindingSummaries(findings []Finding) []expectedFinding {
	out := make([]expectedFinding, 0)
	for _, f := range findings {
		if !f.HardEvidence {
			continue
		}
		out = append(out, expectedFinding{
			Type:             f.Type,
			Detector:         f.Detector,
			EvidenceStrength: string(f.EvidenceStrength),
		})
	}
	return out
}

func findingSortKey(f expectedFinding) string {
	return f.Type + "|" + f.Detector + "|" + f.EvidenceStrength
}
