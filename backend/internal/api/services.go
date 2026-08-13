package api

import (
	"google.golang.org/grpc"

	"manara-dlp/internal/endpoints"
	"manara-dlp/internal/policy"
	"manara-dlp/internal/telemetry"
	pb "manara-dlp/pkg/grpc"
)

// RegisterServices registers all gRPC services
func RegisterServices(
	grpcServer *grpc.Server,
	policyService *policy.Service,
	telemetryService *telemetry.Service,
	endpointService *endpoints.Service,
) {
	// Register gRPC service implementations
	pb.RegisterPolicyServiceServer(grpcServer, &policyGRPCServer{service: policyService})
	pb.RegisterTelemetryServiceServer(grpcServer, &telemetryGRPCServer{service: telemetryService})
	pb.RegisterEndpointServiceServer(grpcServer, &endpointGRPCServer{service: endpointService})
}

// gRPC service implementations (simplified - would need full implementation)
type policyGRPCServer struct {
	pb.UnimplementedPolicyServiceServer
	service *policy.Service
}

type telemetryGRPCServer struct {
	pb.UnimplementedTelemetryServiceServer
	service *telemetry.Service
}

type endpointGRPCServer struct {
	pb.UnimplementedEndpointServiceServer
	service *endpoints.Service
}
