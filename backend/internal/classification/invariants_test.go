package classification

import (
	"math/rand"
	"reflect"
	"strings"
	"testing"
	"testing/quick"
	"unicode/utf8"
)

// --- generators -------------------------------------------------------------

func randomID(r *rand.Rand) string {
	const pool = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 8)
	for i := range b {
		b[i] = pool[r.Intn(len(pool))]
	}
	return string(b)
}

func randomStrength(r *rand.Rand) EvidenceStrength {
	return []EvidenceStrength{
		EvidenceHardValidated,
		EvidenceStrongStructural,
		EvidenceContextual,
		EvidenceWeakHeuristic,
	}[r.Intn(4)]
}

func randomFinding(r *rand.Rand) Finding {
	return Finding{
		ID:               randomID(r),
		Type:             randomID(r),
		Detector:         randomID(r),
		Confidence:       r.Float64(),
		EvidenceStrength: randomStrength(r),
		HardEvidence:     r.Intn(2) == 0,
		Status:           StatusClassified,
		ShadowOnly:       r.Intn(2) == 0,
		StartOffset:      r.Intn(100),
		EndOffset:        r.Intn(100),
	}
}

func shuffleFindings(s []Finding, r *rand.Rand) {
	r.Shuffle(len(s), func(i, j int) { s[i], s[j] = s[j], s[i] })
}

func randomUTF8(r *rand.Rand, n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		switch r.Intn(4) {
		case 0:
			b.WriteRune(rune(r.Intn(26) + 'a'))
		case 1:
			b.WriteRune(rune(r.Intn(0x7FF) + 1))
		case 2:
			b.WriteRune(rune(r.Intn(0xFFFF) + 1))
		default:
			b.WriteRune(rune(r.Intn(0x10FFFF) + 1))
		}
	}
	return b.String()
}

// --- invariants -------------------------------------------------------------

// TestMergePreservesHardFindings asserts MergeFindings never removes a hard
// deterministic finding, regardless of the optional set.
func TestMergePreservesHardFindings(t *testing.T) {
	check := func(dets []Finding, opts []Finding) bool {
		merged := MergeFindings(dets, opts)
		for _, d := range dets {
			if !d.HardEvidence {
				continue
			}
			k := findingKey(d)
			present := false
			for _, m := range merged {
				if findingKey(m) == k && m.HardEvidence {
					present = true
					break
				}
			}
			if !present {
				return false
			}
		}
		return true
	}
	if err := quick.Check(check, &quick.Config{MaxCount: 2000}); err != nil {
		t.Error("hard evidence preservation invariant violated: ", err)
	}
}

// TestMergeNoDowngradeOfHard asserts an optional finding with lower confidence
// cannot reduce the confidence of a conflicting hard finding.
func TestMergeNoDowngradeOfHard(t *testing.T) {
	check := func(conf float64) bool {
		hard := Finding{
			ID: "hard", Type: "x", Detector: "d",
			Confidence:       1.0,
			EvidenceStrength: EvidenceHardValidated,
			HardEvidence:     true,
			Status:           StatusClassified,
		}
		low := Finding{
			ID: "hard", Type: "x", Detector: "d",
			Confidence:       conf,
			EvidenceStrength: EvidenceWeakHeuristic,
			Status:           StatusClassified,
		}
		merged := MergeFindings([]Finding{hard}, []Finding{low})
		return len(merged) == 1 && merged[0].HardEvidence && merged[0].Confidence == 1.0
	}
	if err := quick.Check(check, &quick.Config{MaxCount: 2000}); err != nil {
		t.Error("no-downgrade invariant violated: ", err)
	}
}

// TestMergeShadowDoesNotAffectHard asserts a ShadowOnly optional finding cannot
// change the Status or EvidenceStrength of a conflicting hard finding.
func TestMergeShadowDoesNotAffectHard(t *testing.T) {
	check := func(conf float64, status AnalysisStatus) bool {
		hard := Finding{
			ID: "hard", Type: "x", Detector: "d",
			Confidence:       1.0,
			EvidenceStrength: EvidenceHardValidated,
			HardEvidence:     true,
			Status:           StatusClassified,
		}
		shadow := Finding{
			ID: "hard", Type: "x", Detector: "d",
			Confidence:       conf,
			EvidenceStrength: EvidenceContextual,
			Status:           status,
			ShadowOnly:       true,
		}
		merged := MergeFindings([]Finding{hard}, []Finding{shadow})
		if len(merged) != 1 {
			return false
		}
		m := merged[0]
		return m.HardEvidence && m.Status == StatusClassified && m.EvidenceStrength == EvidenceHardValidated
	}
	if err := quick.Check(check, &quick.Config{MaxCount: 2000}); err != nil {
		t.Error("shadow non-influence invariant violated: ", err)
	}
}

// TestMergeDeterminism asserts the merge result is identical regardless of the
// order of the optional findings.
func TestMergeDeterminism(t *testing.T) {
	for seed := int64(0); seed < 50; seed++ {
		r := rand.New(rand.NewSource(seed))
		dets := make([]Finding, 0, 6)
		for i := 0; i < 6; i++ {
			dets = append(dets, randomFinding(r))
		}
		opts := make([]Finding, 0, 30)
		for i := 0; i < 30; i++ {
			opts = append(opts, randomFinding(r))
		}

		a := append([]Finding(nil), opts...)
		b := append([]Finding(nil), opts...)
		shuffleFindings(a, r)
		shuffleFindings(b, r)

		m1 := MergeFindings(dets, a)
		m2 := MergeFindings(dets, b)
		if !reflect.DeepEqual(m1, m2) {
			t.Fatalf("seed %d: merge is not order-independent:\n%+v\n%+v", seed, m1, m2)
		}
	}
}

// TestExtractMatchLocalContextBounds asserts random invocations never exceed
// the maximum context size, produce valid UTF-8, and never panic.
func TestExtractMatchLocalContextBounds(t *testing.T) {
	r := rand.New(rand.NewSource(7))
	for i := 0; i < 5000; i++ {
		text := randomUTF8(r, r.Intn(400))
		offset := r.Intn(len(text)+10) - 5
		length := r.Intn(60)
		ctxSize := r.Intn(700)

		got := ExtractMatchLocalContext(text, offset, length, ctxSize)
		if !utf8.ValidString(got) {
			t.Fatalf("iter %d: context is not valid UTF-8: %q", i, got)
		}
		if n := utf8.RuneCountInString(got); n > maxMatchContextSize {
			t.Fatalf("iter %d: context length %d exceeds max %d", i, n, maxMatchContextSize)
		}
	}
}
