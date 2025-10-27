package stratium

import (
	"context"
	"fmt"

	"google.golang.org/grpc"
)

// PlatformClient provides methods for making authorization decisions.
//
// The Platform service evaluates authorization requests against policies
// and entitlements to determine if access should be granted.
type PlatformClient struct {
	conn   *grpc.ClientConn
	config *Config
	auth   *authManager

	// TODO: Add generated proto client when available
	// client platform.PlatformServiceClient
}

// Decision represents an authorization decision.
type Decision int32

const (
	DecisionDeny        Decision = 0
	DecisionAllow       Decision = 1
	DecisionConditional Decision = 2
)

// AuthorizationRequest contains the parameters for an authorization decision.
type AuthorizationRequest struct {
	// Subject attributes (user/client making the request)
	SubjectAttributes map[string]string

	// Resource attributes (what is being accessed)
	ResourceAttributes map[string]string

	// Action being performed (e.g., "read", "write", "delete")
	Action string

	// Additional context for the decision
	Context map[string]string
}

// AuthorizationResponse contains the result of an authorization decision.
type AuthorizationResponse struct {
	Decision        Decision          // The authorization decision
	Reason          string            // Explanation for the decision
	EvaluatedPolicy string            // Policy that made the decision
	Details         map[string]string // Additional details
	Timestamp       string            // When the decision was made
}

// Entitlement represents an access entitlement.
type Entitlement struct {
	ID                 string
	Subject            string
	Resource           string
	Actions            []string
	Conditions         []Condition
	Active             bool
	ResourceAttributes map[string]string
}

// Condition represents a conditional access requirement.
type Condition struct {
	Type       string            // Type of condition (e.g., "time", "attribute")
	Operator   string            // Operator (e.g., "equals", "contains", "before", "after")
	Value      string            // Value to compare against
	Parameters map[string]string // Additional parameters
}

// newPlatformClient creates a new Platform client.
func newPlatformClient(conn *grpc.ClientConn, config *Config, auth *authManager) *PlatformClient {
	return &PlatformClient{
		conn:   conn,
		config: config,
		auth:   auth,
		// client: platform.NewPlatformServiceClient(conn),
	}
}

// GetDecision makes an authorization decision for the given request.
//
// This is the primary method for checking if a subject (user/client) is
// authorized to perform an action on a resource.
//
// Example:
//
//	decision, err := client.Platform.GetDecision(ctx, &stratium.AuthorizationRequest{
//	    SubjectAttributes: map[string]string{
//	        "sub":        "user123",
//	        "email":      "user@example.com",
//	        "department": "engineering",
//	    },
//	    ResourceAttributes: map[string]string{
//	        "name": "document-service",
//	        "type": "service",
//	    },
//	    Action: "read",
//	    Context: map[string]string{
//	        "ip_address": "192.168.1.100",
//	    },
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	if decision.Decision == stratium.DecisionAllow {
//	    // Grant access
//	} else {
//	    // Deny access
//	    log.Printf("Access denied: %s", decision.Reason)
//	}
func (c *PlatformClient) GetDecision(ctx context.Context, req *AuthorizationRequest) (*AuthorizationResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("request cannot be nil")
	}
	if req.Action == "" {
		return nil, fmt.Errorf("action is required")
	}
	if len(req.SubjectAttributes) == 0 {
		return nil, fmt.Errorf("subject_attributes are required")
	}

	// Validate subject has an identifier
	if _, ok := req.SubjectAttributes["sub"]; !ok {
		if _, ok := req.SubjectAttributes["user_id"]; !ok {
			if _, ok := req.SubjectAttributes["id"]; !ok {
				return nil, fmt.Errorf("subject_attributes must contain 'sub', 'user_id', or 'id'")
			}
		}
	}

	token := ""
	if c.auth != nil {
		var err error
		token, err = c.auth.GetToken(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get auth token: %w", err)
		}
	}

	ctx, cancel := c.config.contextWithTimeout(ctx)
	defer cancel()
	ctx = contextWithAuth(ctx, token)

	// TODO: Call gRPC service
	// resp, err := c.client.GetDecision(ctx, &platform.GetDecisionRequest{...})

	return nil, fmt.Errorf("not implemented - protobuf stubs need to be generated")
}

// GetEntitlements retrieves all entitlements for a subject.
//
// Example:
//
//	entitlements, err := client.Platform.GetEntitlements(ctx, map[string]string{
//	    "sub": "user123",
//	})
func (c *PlatformClient) GetEntitlements(ctx context.Context, subjectAttributes map[string]string) ([]*Entitlement, error) {
	if len(subjectAttributes) == 0 {
		return nil, fmt.Errorf("subject_attributes are required")
	}

	// Validate subject has an identifier
	if _, ok := subjectAttributes["sub"]; !ok {
		if _, ok := subjectAttributes["user_id"]; !ok {
			if _, ok := subjectAttributes["id"]; !ok {
				return nil, fmt.Errorf("subject_attributes must contain 'sub', 'user_id', or 'id'")
			}
		}
	}

	token := ""
	if c.auth != nil {
		var err error
		token, err = c.auth.GetToken(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get auth token: %w", err)
		}
	}

	ctx, cancel := c.config.contextWithTimeout(ctx)
	defer cancel()
	ctx = contextWithAuth(ctx, token)

	// TODO: Call gRPC service
	// resp, err := c.client.GetEntitlements(ctx, &platform.GetEntitlementsRequest{...})

	return nil, fmt.Errorf("not implemented - protobuf stubs need to be generated")
}

// CheckAccess is a convenience method that returns true if access is allowed.
//
// Example:
//
//	allowed, err := client.Platform.CheckAccess(ctx, &stratium.AuthorizationRequest{
//	    SubjectAttributes: map[string]string{"sub": "user123"},
//	    ResourceAttributes: map[string]string{"name": "document-service"},
//	    Action: "read",
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	if allowed {
//	    // Grant access
//	} else {
//	    // Deny access
//	}
func (c *PlatformClient) CheckAccess(ctx context.Context, req *AuthorizationRequest) (bool, error) {
	decision, err := c.GetDecision(ctx, req)
	if err != nil {
		return false, err
	}
	return decision.Decision == DecisionAllow, nil
}
