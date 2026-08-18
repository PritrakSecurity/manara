package api

import (
	"encoding/json"

	"manara-dlp/internal/classification"
)

// findingView is the privacy-safe projection of a classification Finding
// exposed over the API. Raw context excerpts, matched secret values, offsets,
// and provider request/response payloads are never serialized.
type findingView struct {
	Type             string `json:"type"`
	Detector         string `json:"detector"`
	EvidenceStrength string `json:"evidence_strength"`
	HardEvidence     bool   `json:"hard_evidence"`
	Status           string `json:"status"`
	ShadowOnly       bool   `json:"shadow_only"`
}

// toFindingViews projects findings to their privacy-safe representation. It
// returns nil for an empty input so the API omits the field entirely.
func toFindingViews(findings []classification.Finding) []findingView {
	if len(findings) == 0 {
		return nil
	}
	views := make([]findingView, 0, len(findings))
	for _, f := range findings {
		views = append(views, findingView{
			Type:             f.Type,
			Detector:         f.Detector,
			EvidenceStrength: string(f.EvidenceStrength),
			HardEvidence:     f.HardEvidence,
			Status:           string(f.Status),
			ShadowOnly:       f.ShadowOnly,
		})
	}
	return views
}

// marshalFindings serializes findings as their privacy-safe views for JSONB
// storage. It returns (nil, nil) when there are no findings.
func marshalFindings(findings []classification.Finding) ([]byte, error) {
	views := toFindingViews(findings)
	if views == nil {
		return nil, nil
	}
	return json.Marshal(views)
}
