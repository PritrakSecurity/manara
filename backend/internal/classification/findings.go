package classification

import (
	"fmt"
	"sort"
)

// AnalysisStatus describes the outcome of an analysis pass.
type AnalysisStatus string

const (
	StatusClassified   AnalysisStatus = "classified"
	StatusAbstained    AnalysisStatus = "abstained"
	StatusUnsupported  AnalysisStatus = "unsupported"
	StatusTimedOut     AnalysisStatus = "timed_out"
	StatusUnavailable  AnalysisStatus = "unavailable"
	StatusInvalidInput AnalysisStatus = "invalid_input"
)

// EvidenceStrength describes how strongly a finding is supported.
type EvidenceStrength string

const (
	EvidenceHardValidated    EvidenceStrength = "hard_validated"
	EvidenceStrongStructural EvidenceStrength = "strong_structural"
	EvidenceContextual       EvidenceStrength = "contextual"
	EvidenceWeakHeuristic    EvidenceStrength = "weak_heuristic"
)

// ProviderMetadata carries provenance and runtime metadata for a finding.
type ProviderMetadata struct {
	Provider        string
	AdapterVersion  string
	ContractVersion string
	ModelID         string
	ModelVersion    string
	ExecutionMode   string
	Status          string
	LatencyMs       int
	TaxonomyVersion string
}

// Finding is a structured classification result produced by a detector
// (deterministic rule engine or optional AI provider).
type Finding struct {
	ID               string
	Type             string
	Category         string
	Detector         string
	Provider         string
	SourcePhase      string
	Confidence       float64
	EvidenceStrength EvidenceStrength
	HardEvidence     bool
	StartOffset      int
	EndOffset        int
	Status           AnalysisStatus
	ReasonCode       string
	ContractVersion  string
	ProviderMetadata ProviderMetadata
	ShadowOnly       bool
}

// Validate checks the invariants of a Finding.
func (f Finding) Validate() error {
	if f.Confidence < 0 || f.Confidence > 1 {
		return fmt.Errorf("finding %q: confidence %v out of range [0,1]", f.ID, f.Confidence)
	}
	switch f.Status {
	case StatusClassified, StatusAbstained, StatusUnsupported, StatusTimedOut, StatusUnavailable, StatusInvalidInput:
	default:
		return fmt.Errorf("finding %q: invalid status %q", f.ID, f.Status)
	}
	if f.HardEvidence {
		if f.EvidenceStrength != EvidenceHardValidated && f.EvidenceStrength != EvidenceStrongStructural {
			return fmt.Errorf("finding %q: hard evidence requires evidence strength %q or %q, got %q", f.ID, EvidenceHardValidated, EvidenceStrongStructural, f.EvidenceStrength)
		}
	}
	if f.ShadowOnly {
		if f.Status != StatusClassified && f.Status != StatusAbstained {
			return fmt.Errorf("finding %q: shadow-only finding must have status %q or %q, got %q", f.ID, StatusClassified, StatusAbstained, f.Status)
		}
	}
	return nil
}

var evidenceRank = map[EvidenceStrength]int{
	EvidenceWeakHeuristic:    0,
	EvidenceContextual:       1,
	EvidenceStrongStructural: 2,
	EvidenceHardValidated:    3,
}

// MergeFindings merges deterministic (local rule engine) findings with
// optional (AI provider) findings.
//
// Invariants:
//  1. Hard deterministic findings are never removed by optional providers.
//  2. Hard findings are never downgraded: confidence and evidence strength
//     can only stay equal or increase.
//  3. A conflict between an optional finding and a hard finding is won by
//     the hard finding.
//  4. The result is deterministic regardless of the order of optional findings.
func MergeFindings(deterministic []Finding, optional []Finding) []Finding {
	merged := make([]Finding, 0, len(deterministic)+len(optional))
	byKey := make(map[string]int)

	for _, f := range deterministic {
		k := findingKey(f)
		if idx, ok := byKey[k]; ok {
			merged[idx] = mergeInto(merged[idx], f)
			continue
		}
		byKey[k] = len(merged)
		merged = append(merged, f)
	}

	for _, f := range optional {
		k := findingKey(f)
		idx, ok := byKey[k]
		if !ok {
			byKey[k] = len(merged)
			merged = append(merged, f)
			continue
		}
		if merged[idx].HardEvidence {
			continue
		}
		merged[idx] = mergeInto(merged[idx], f)
	}

	sort.Slice(merged, func(i, j int) bool {
		return findingKey(merged[i]) < findingKey(merged[j])
	})

	return merged
}

// findingKey returns a stable identity for a finding used for merging and
// ordering. Findings without an explicit ID are keyed by their location and
// source so the merge is deterministic regardless of provider order.
func findingKey(f Finding) string {
	if f.ID != "" {
		return "id:" + f.ID
	}
	return fmt.Sprintf("type:%s|detector:%s|offset:%d:%d", f.Type, f.Detector, f.StartOffset, f.EndOffset)
}

// mergeInto upgrades dst with anything strictly better in b: confidence,
// evidence strength, and hard-evidence flag. It never downgrades dst.
func mergeInto(dst, b Finding) Finding {
	if b.HardEvidence {
		dst.HardEvidence = true
	}
	if evidenceRank[b.EvidenceStrength] > evidenceRank[dst.EvidenceStrength] {
		dst.EvidenceStrength = b.EvidenceStrength
	}
	if b.Confidence > dst.Confidence {
		dst.Confidence = b.Confidence
	}
	return dst
}
