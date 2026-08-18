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

// errPresidio is the sanitized error surface for Presidio provider failures.
// Raw provider errors are never propagated because they may echo the submitted
// text.
var errPresidio = errors.New("presidio analysis provider error")

// presidioEntity mirrors the JSON entities returned by the Presidio /analyze
// endpoint.
type presidioEntity struct {
	EntityType string  `json:"entity_type"`
	Text       string  `json:"text"`
	Start      int     `json:"start"`
	End        int     `json:"end"`
	Score      float64 `json:"score"`
}

// presidioAnalyzeRequest is the privacy-bounded payload sent to Presidio. Only
// the bounded context text and language are submitted; nothing else from the
// document ever leaves the engine.
type presidioAnalyzeRequest struct {
	Text     string `json:"text"`
	Language string `json:"language"`
}

// PresidioProvider implements AnalysisProvider against a Presidio analyzer
// instance. It never logs the submitted text or the response body, and it
// returns only sanitized errors.
type PresidioProvider struct {
	url     string
	client  *http.Client
	timeout time.Duration
}

// NewPresidioProvider builds a Presidio-backed analysis provider.
func NewPresidioProvider(url string, client *http.Client, timeout time.Duration) *PresidioProvider {
	if client == nil {
		client = &http.Client{Timeout: timeout}
	}
	return &PresidioProvider{url: url, client: client, timeout: timeout}
}

// Analyze submits the bounded context to the Presidio /analyze endpoint and
// maps the recognized entities to Findings. Timeouts map to timed_out, any
// other transport/server failure maps to unavailable, and errors never carry
// the submitted text.
func (p *PresidioProvider) Analyze(ctx context.Context, req AnalysisRequest) (AnalysisResponse, error) {
	if strings.TrimSpace(p.url) == "" {
		return AnalysisResponse{RequestID: req.RequestID, Status: StatusUnavailable}, errPresidio
	}

	timeout := p.timeout
	if req.Deadline > 0 && req.Deadline < timeout {
		timeout = req.Deadline
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	language := req.LanguageHint
	if language == "" {
		language = "en"
	}
	body, err := json.Marshal(presidioAnalyzeRequest{Text: req.BoundedContext, Language: language})
	if err != nil {
		return AnalysisResponse{RequestID: req.RequestID, Status: StatusUnavailable}, errPresidio
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(p.url, "/")+"/analyze", bytes.NewReader(body))
	if err != nil {
		return AnalysisResponse{RequestID: req.RequestID, Status: StatusUnavailable}, errPresidio
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(httpReq)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return AnalysisResponse{RequestID: req.RequestID, Status: StatusTimedOut}, errPresidio
		}
		return AnalysisResponse{RequestID: req.RequestID, Status: StatusUnavailable}, errPresidio
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return AnalysisResponse{RequestID: req.RequestID, Status: StatusUnavailable}, errPresidio
	}

	var entities []presidioEntity
	if err := json.NewDecoder(resp.Body).Decode(&entities); err != nil {
		return AnalysisResponse{RequestID: req.RequestID, Status: StatusUnavailable}, errPresidio
	}

	findings := make([]Finding, 0, len(entities))
	for _, e := range entities {
		findings = append(findings, Finding{
			Type:             e.EntityType,
			Detector:         "presidio",
			Provider:         "presidio",
			SourcePhase:      "phase2.5",
			Confidence:       e.Score,
			EvidenceStrength: EvidenceContextual,
			StartOffset:      e.Start,
			EndOffset:        e.End,
			Status:           StatusClassified,
		})
	}

	return AnalysisResponse{
		RequestID:        req.RequestID,
		Status:           StatusClassified,
		Findings:         findings,
		ProviderMetadata: ProviderMetadata{Provider: "presidio"},
	}, nil
}
