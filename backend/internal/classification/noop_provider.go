package classification

import "context"

// NoOpProvider is the default analysis provider used when AI is disabled. It
// always abstains and returns no findings, keeping the engine deterministic.
type NoOpProvider struct{}

// Analyze immediately returns an abstained response with empty findings.
func (NoOpProvider) Analyze(ctx context.Context, req AnalysisRequest) (AnalysisResponse, error) {
	return AnalysisResponse{
		ContractVersion: req.ContractVersion,
		RequestID:       req.RequestID,
		Status:          StatusAbstained,
		Findings:        []Finding{},
	}, nil
}
