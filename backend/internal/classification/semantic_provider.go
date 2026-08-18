package classification

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

// errSemantic is the sanitized error surface for the semantic classifier
// provider. Raw provider errors are never propagated because they may echo the
// submitted text.
var errSemantic = errors.New("semantic classifier provider error")

// SemanticProvider implements AnalysisProvider against a semantic classifier
// service. It always runs in shadow mode: every finding it returns is marked
// ShadowOnly so it can never influence enforcement. It never logs the
// submitted text or the response body, and it returns only sanitized errors.
type SemanticProvider struct {
	url     string
	client  *http.Client
	timeout time.Duration
}

// NewSemanticProvider builds a semantic classifier-backed analysis provider.
func NewSemanticProvider(url string, client *http.Client, timeout time.Duration) *SemanticProvider {
	if client == nil {
		client = &http.Client{Timeout: timeout}
	}
	return &SemanticProvider{url: url, client: client, timeout: timeout}
}

// Analyze submits the privacy-bounded request to the semantic classifier
// /classify endpoint and maps the returned findings to shadow-only Findings.
// Timeouts map to timed_out, any other transport/server failure maps to
// unavailable, and errors never carry the submitted text.
func (p *SemanticProvider) Analyze(ctx context.Context, req AnalysisRequest) (AnalysisResponse, error) {
	if strings.TrimSpace(p.url) == "" {
		return AnalysisResponse{RequestID: req.RequestID, Status: StatusUnavailable}, errSemantic
	}

	timeout := p.timeout
	if req.Deadline > 0 && req.Deadline < timeout {
		timeout = req.Deadline
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	payload := SemanticRequest{
		ContractVersion:   semanticContractVersion,
		RequestID:         req.RequestID,
		AmbiguousFindings: req.AmbiguousFindings,
		BoundedContext:    req.BoundedContext,
		LanguageHint:      req.LanguageHint,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return AnalysisResponse{RequestID: req.RequestID, Status: StatusUnavailable}, errSemantic
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(p.url, "/")+"/classify", bytes.NewReader(body))
	if err != nil {
		return AnalysisResponse{RequestID: req.RequestID, Status: StatusUnavailable}, errSemantic
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(httpReq)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return AnalysisResponse{RequestID: req.RequestID, Status: StatusTimedOut}, errSemantic
		}
		return AnalysisResponse{RequestID: req.RequestID, Status: StatusUnavailable}, errSemantic
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return AnalysisResponse{RequestID: req.RequestID, Status: StatusUnavailable}, errSemantic
	}

	var semantic SemanticResponse
	if err := json.NewDecoder(resp.Body).Decode(&semantic); err != nil {
		return AnalysisResponse{RequestID: req.RequestID, Status: StatusUnavailable}, errSemantic
	}

	// Shadow mode: findings can be recorded for evaluation but must never
	// influence enforcement decisions.
	findings := make([]Finding, 0, len(semantic.Findings))
	for _, f := range semantic.Findings {
		f.ShadowOnly = true
		f.SourcePhase = "phase2.5-shadow"
		f.Provider = "semantic"
		f.Status = StatusClassified
		findings = append(findings, f)
	}

	status := semantic.Status
	if status == "" {
		status = StatusClassified
	}

	return AnalysisResponse{
		ContractVersion:  semantic.ContractVersion,
		RequestID:        req.RequestID,
		Status:           status,
		Findings:         findings,
		ProviderMetadata: semantic.ProviderMetadata,
	}, nil
}
