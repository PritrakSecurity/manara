package classification

import (
	"reflect"
	"testing"
)

func validFinding() Finding {
	return Finding{
		ID:               "f-1",
		Type:             "secret",
		Category:         "aws",
		Detector:         "rule-aws-access-key",
		Confidence:       0.9,
		EvidenceStrength: EvidenceHardValidated,
		HardEvidence:     true,
		Status:           StatusClassified,
	}
}

func TestValidateConfidenceBounds(t *testing.T) {
	tests := []struct {
		name       string
		confidence float64
		wantErr    bool
	}{
		{name: "zero is valid", confidence: 0.0, wantErr: false},
		{name: "one is valid", confidence: 1.0, wantErr: false},
		{name: "mid range is valid", confidence: 0.5, wantErr: false},
		{name: "negative is invalid", confidence: -0.1, wantErr: true},
		{name: "above one is invalid", confidence: 1.1, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := validFinding()
			f.Confidence = tt.confidence
			err := f.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateInvalidStatus(t *testing.T) {
	tests := []struct {
		name    string
		status  AnalysisStatus
		wantErr bool
	}{
		{name: "valid statuses", status: StatusAbstained, wantErr: false},
		{name: "invalid status", status: AnalysisStatus("bogus"), wantErr: true},
		{name: "empty status", status: AnalysisStatus(""), wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := validFinding()
			f.HardEvidence = false
			f.Status = tt.status
			err := f.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateHardEvidenceStrength(t *testing.T) {
	tests := []struct {
		name     string
		strength EvidenceStrength
		hard     bool
		wantErr  bool
	}{
		{name: "hard evidence with hard_validated", strength: EvidenceHardValidated, hard: true, wantErr: false},
		{name: "hard evidence with strong_structural", strength: EvidenceStrongStructural, hard: true, wantErr: false},
		{name: "hard evidence with contextual", strength: EvidenceContextual, hard: true, wantErr: true},
		{name: "hard evidence with weak_heuristic", strength: EvidenceWeakHeuristic, hard: true, wantErr: true},
		{name: "non-hard evidence with weak_heuristic", strength: EvidenceWeakHeuristic, hard: false, wantErr: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := validFinding()
			f.HardEvidence = tt.hard
			f.EvidenceStrength = tt.strength
			err := f.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateShadowOnly(t *testing.T) {
	tests := []struct {
		name    string
		status  AnalysisStatus
		wantErr bool
	}{
		{name: "shadow only classified", status: StatusClassified, wantErr: false},
		{name: "shadow only abstained", status: StatusAbstained, wantErr: false},
		{name: "shadow only unsupported", status: StatusUnsupported, wantErr: true},
		{name: "shadow only timed_out", status: StatusTimedOut, wantErr: true},
		{name: "shadow only unavailable", status: StatusUnavailable, wantErr: true},
		{name: "shadow only invalid_input", status: StatusInvalidInput, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := validFinding()
			f.HardEvidence = false
			f.Status = tt.status
			f.ShadowOnly = true
			err := f.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v, wantErr = %v", err, tt.wantErr)
			}
		})
	}
}

func TestMergeFindingsHardFindingNotOverwritten(t *testing.T) {
	hard := validFinding()
	optional := Finding{
		ID:               hard.ID,
		Type:             "different",
		Detector:         "ai-llm",
		Confidence:       1.0,
		EvidenceStrength: EvidenceContextual,
		Status:           StatusClassified,
	}

	merged := MergeFindings([]Finding{hard}, []Finding{optional})

	if len(merged) != 1 {
		t.Fatalf("expected 1 merged finding, got %d", len(merged))
	}
	if !reflect.DeepEqual(merged[0], hard) {
		t.Fatalf("hard finding was overwritten: got %+v, want %+v", merged[0], hard)
	}
}

func TestMergeFindingsOptionalCannotLowerHardConfidence(t *testing.T) {
	hard := validFinding()
	hard.Confidence = 0.9

	optionalLow := Finding{
		ID:               hard.ID,
		Detector:         "ai-llm",
		Confidence:       0.4,
		EvidenceStrength: EvidenceContextual,
		Status:           StatusClassified,
	}

	merged := MergeFindings([]Finding{hard}, []Finding{optionalLow})

	if len(merged) != 1 {
		t.Fatalf("expected 1 merged finding, got %d", len(merged))
	}
	if merged[0].Confidence != 0.9 {
		t.Fatalf("hard finding confidence lowered to %v, want 0.9", merged[0].Confidence)
	}
	if merged[0].EvidenceStrength != EvidenceHardValidated {
		t.Fatalf("hard finding evidence downgraded to %q, want %q", merged[0].EvidenceStrength, EvidenceHardValidated)
	}
	if !merged[0].HardEvidence {
		t.Fatal("hard finding lost HardEvidence flag")
	}
}

func TestMergeFindingsOrderIndependence(t *testing.T) {
	hard := validFinding()

	optA := Finding{ID: "opt-a", Detector: "ai-llm", Confidence: 0.6, EvidenceStrength: EvidenceContextual, Status: StatusClassified}
	optB := Finding{ID: "opt-b", Detector: "ai-llm", Confidence: 0.5, EvidenceStrength: EvidenceWeakHeuristic, Status: StatusClassified}

	deterministic := []Finding{hard}

	first := MergeFindings(deterministic, []Finding{optA, optB})
	second := MergeFindings(deterministic, []Finding{optB, optA})

	if len(first) != len(second) {
		t.Fatalf("merge results differ in length: %d vs %d", len(first), len(second))
	}
	for i := range first {
		if !reflect.DeepEqual(first[i], second[i]) {
			t.Fatalf("merge results differ at index %d:\n got  %+v\n want %+v", i, first[i], second[i])
		}
	}
}

func TestMergeFindingsOptionalConflictingHardIsDropped(t *testing.T) {
	hard := validFinding()

	conflicting := Finding{
		ID:               hard.ID,
		Detector:         "ai-llm",
		Type:             "different",
		Confidence:       1.0,
		EvidenceStrength: EvidenceHardValidated,
		HardEvidence:     true,
		Status:           StatusClassified,
	}

	merged := MergeFindings([]Finding{hard}, []Finding{conflicting})

	if len(merged) != 1 {
		t.Fatalf("expected 1 merged finding, got %d", len(merged))
	}
	if !reflect.DeepEqual(merged[0], hard) {
		t.Fatalf("hard finding lost to conflicting optional finding: got %+v, want %+v", merged[0], hard)
	}
}

func TestMergeFindingsAddsNonConflictingOptional(t *testing.T) {
	hard := validFinding()
	extra := Finding{
		ID:               "opt-new",
		Detector:         "ai-llm",
		Confidence:       0.5,
		EvidenceStrength: EvidenceContextual,
		Status:           StatusClassified,
	}

	merged := MergeFindings([]Finding{hard}, []Finding{extra})

	if len(merged) != 2 {
		t.Fatalf("expected 2 merged findings, got %d", len(merged))
	}
	if merged[0].ID != hard.ID && merged[1].ID != hard.ID {
		t.Fatalf("hard finding missing from merge result: %+v", merged)
	}
	if merged[0].ID != extra.ID && merged[1].ID != extra.ID {
		t.Fatalf("optional finding missing from merge result: %+v", merged)
	}
}
