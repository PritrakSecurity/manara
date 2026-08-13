package auth

import (
	"context"
	"crypto/x509"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// UnaryAuthInterceptor performs mTLS authentication for gRPC calls
func UnaryAuthInterceptor(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	// Extract peer information
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil, status.Errorf(codes.Unauthenticated, "peer information not available")
	}

	// Verify TLS connection
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return nil, status.Errorf(codes.Unauthenticated, "not a TLS connection")
	}

	// Extract client certificate
	if len(tlsInfo.State.PeerCertificates) == 0 {
		return nil, status.Errorf(codes.Unauthenticated, "no client certificate provided")
	}

	clientCert := tlsInfo.State.PeerCertificates[0]

	// Verify certificate common name (CN) matches expected pattern
	// Expected format: agent-<endpoint-id> or admin-<user-id>
	cn := clientCert.Subject.CommonName
	if !isValidCN(cn) {
		return nil, status.Errorf(codes.Unauthenticated, "invalid certificate CN: %s", cn)
	}

	// Add certificate info to context for downstream use
	ctx = context.WithValue(ctx, "client_cn", cn)
	ctx = context.WithValue(ctx, "client_cert", clientCert)

	return handler(ctx, req)
}

// isValidCN validates certificate common name format
func isValidCN(cn string) bool {
	if cn == "" {
		return false
	}

	// Allow agent-* or admin-* prefixes
	return strings.HasPrefix(cn, "agent-") || strings.HasPrefix(cn, "admin-")
}

// GetClientCN extracts client CN from context
func GetClientCN(ctx context.Context) (string, bool) {
	cn, ok := ctx.Value("client_cn").(string)
	return cn, ok
}

// GetClientCert extracts client certificate from context
func GetClientCert(ctx context.Context) (*x509.Certificate, bool) {
	cert, ok := ctx.Value("client_cert").(*x509.Certificate)
	return cert, ok
}
