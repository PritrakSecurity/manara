package classification

// semanticContractVersion is the wire contract version spoken between the
// engine and the semantic classifier service.
const semanticContractVersion = "v1"

// SemanticRequest is the privacy-bounded payload sent to the semantic
// classifier service. It only carries the ambiguous findings and their bounded
// context — never raw files or unrelated findings — and no verdict or
// enforcement fields.
type SemanticRequest struct {
	ContractVersion   string    `json:"contract_version"`
	RequestID         string    `json:"request_id"`
	AmbiguousFindings []Finding `json:"ambiguous_findings"`
	BoundedContext    string    `json:"bounded_context"`
	LanguageHint      string    `json:"language_hint"`
	TaxonomyVersion   string    `json:"taxonomy_version"`
}

// SemanticResponse is the result returned by the semantic classifier service.
// It only carries findings plus provenance metadata; it never contains verdict
// or enforcement decisions (no allow/deny/block/quarantine/policy fields).
type SemanticResponse struct {
	ContractVersion  string           `json:"contract_version"`
	RequestID        string           `json:"request_id"`
	Status           AnalysisStatus   `json:"status"`
	Findings         []Finding        `json:"findings"`
	ProviderMetadata ProviderMetadata `json:"provider_metadata"`
}
