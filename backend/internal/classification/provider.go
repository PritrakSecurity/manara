package classification

import (
	"context"
	"fmt"
	"time"
)

// forbiddenVerdictKeys are dynamic metadata keys that a provider is never
// allowed to return. Verdicts and enforcement decisions must be made by the
// deterministic engine, never by an optional provider.
var forbiddenVerdictKeys = map[string]struct{}{
	"allow":              {},
	"deny":               {},
	"block":              {},
	"quarantine":         {},
	"enforcement_action": {},
	"policy_decision":    {},
}

// AnalysisRequest is the privacy-bounded payload sent to an analysis
// provider. It only contains allowlisted fields; it never carries raw
// document content beyond the bounded context, and no verdict or
// enforcement fields.
type AnalysisRequest struct {
	ContractVersion   string
	RequestID         string
	AmbiguousFindings []Finding
	BoundedContext    string
	ContentType       string
	LanguageHint      string
	Deadline          time.Duration
}

// AnalysisResponse is the result returned by an analysis provider. It only
// carries findings plus provenance metadata; it never returns verdict or
// enforcement decisions.
type AnalysisResponse struct {
	ContractVersion  string
	RequestID        string
	Status           AnalysisStatus
	Findings         []Finding
	ProviderMetadata ProviderMetadata
	Metadata         map[string]interface{}
}

// AnalysisProvider is the replaceable AI-analysis backend.
type AnalysisProvider interface {
	Analyze(ctx context.Context, req AnalysisRequest) (AnalysisResponse, error)
}

// ValidateResponse rejects responses that carry forbidden verdict or
// enforcement keys in their dynamic metadata.
func ValidateResponse(resp AnalysisResponse) error {
	for key := range resp.Metadata {
		if _, ok := forbiddenVerdictKeys[key]; ok {
			return fmt.Errorf("response contains forbidden verdict field %q", key)
		}
	}
	return nil
}
