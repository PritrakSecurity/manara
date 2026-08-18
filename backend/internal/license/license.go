// Package license provides a minimal, deployment-controlled feature gate for
// product capabilities such as Cloud DSPM.
//
// It deliberately knows nothing about customer entitlements, signing keys, or
// licensing servers. Feature enablement is configured at startup from the
// LICENSE_FEATURES environment variable (comma-separated feature names), so
// operators can enable or disable capabilities without recompiling.
package license

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// Feature identifies a licensable product capability.
type Feature string

const (
	// FeatureCloudDSPM gates the cloud data security posture management APIs.
	FeatureCloudDSPM Feature = "cloud-dspm"
)

// Service reports whether product features are enabled for this deployment.
type Service struct {
	enabled map[Feature]bool
}

// NewService builds a feature service from a list of enabled feature names.
// Names are lower-cased and trimmed; unknown or empty names are ignored.
// Underscores in the input are normalized to hyphens so both spellings of a
// feature (e.g. "cloud_dspm" and "cloud-dspm") enable the same capability.
func NewService(enabledFeatures []string) *Service {
	s := &Service{enabled: make(map[Feature]bool)}
	for _, name := range enabledFeatures {
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" {
			continue
		}
		name = strings.ReplaceAll(name, "_", "-")
		s.enabled[Feature(name)] = true
	}
	return s
}

// Enabled reports whether the given feature is enabled on this deployment.
// A nil service is treated as fully locked down: no features are enabled.
func (s *Service) Enabled(f Feature) bool {
	if s == nil {
		return false
	}
	return s.enabled[f]
}

// FeatureNames returns the sorted list of enabled feature names. It is useful
// for startup logging and auditing; it never contains sensitive values.
func (s *Service) FeatureNames() []string {
	if s == nil {
		return nil
	}
	names := make([]string, 0, len(s.enabled))
	for name, on := range s.enabled {
		if on {
			names = append(names, string(name))
		}
	}
	sort.Strings(names)
	return names
}

// RequireFeature wraps a handler with a licensing gate. Requests for a feature
// that is not enabled on this deployment are rejected with HTTP 403 and a
// non-sensitive error body. The wrapped handler is never invoked.
func RequireFeature(licSvc *Service, feature Feature, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !licSvc.Enabled(feature) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "feature_not_enabled",
				"message": fmt.Sprintf("The %q feature is not enabled on this deployment", feature),
			})
			return
		}
		next(w, r)
	}
}