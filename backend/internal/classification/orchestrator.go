package classification

import (
	"context"
	"errors"
	"time"
)

// defaultProviderDeadline is the analysis timeout applied when a request does
// not specify one.
const defaultProviderDeadline = 5 * time.Second

// errProvider is the sanitized error surface for provider failures. Raw
// provider errors are never propagated because they may echo request content.
var errProvider = errors.New("analysis provider error")

// Orchestrator dispatches analysis requests to a configured provider and maps
// provider outcomes (timeouts, unavailability) onto the AnalysisStatus enum.
type Orchestrator struct {
	provider AnalysisProvider
}

// NewOrchestrator creates an orchestrator around the given provider.
func NewOrchestrator(provider AnalysisProvider) *Orchestrator {
	return &Orchestrator{provider: provider}
}

// Execute runs a single analysis request against the provider.
//
// The request deadline is enforced via a context timeout. If the deadline is
// exceeded the response status is timed_out; if the provider itself cannot be
// reached the status is unavailable. Responses carrying forbidden verdict
// fields are rejected. Raw content is never leaked into error messages.
func (o *Orchestrator) Execute(ctx context.Context, req AnalysisRequest) (AnalysisResponse, error) {
	if o.provider == nil {
		return AnalysisResponse{RequestID: req.RequestID, Status: StatusUnavailable}, errProvider
	}

	resp := AnalysisResponse{RequestID: req.RequestID, Status: StatusUnavailable}

	timeout := req.Deadline
	if timeout <= 0 {
		timeout = defaultProviderDeadline
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	out, err := o.provider.Analyze(ctx, req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || ctx.Err() == context.DeadlineExceeded {
			resp.Status = StatusTimedOut
		} else {
			resp.Status = StatusUnavailable
		}
		return resp, errProvider
	}

	// A provider that returned after the deadline, even without an error, must
	// not be allowed to influence the result.
	if ctx.Err() == context.DeadlineExceeded {
		resp.Status = StatusTimedOut
		return resp, errProvider
	}

	if err := ValidateResponse(out); err != nil {
		return AnalysisResponse{RequestID: req.RequestID, Status: StatusInvalidInput}, err
	}

	out.RequestID = req.RequestID
	return out, nil
}
