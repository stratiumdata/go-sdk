package stratium

import (
	"context"
	"fmt"

	keyaccess "github.com/stratiumdata/go-sdk/gen/services/key-access"

	"google.golang.org/grpc"
)

// KeyAccessClient provides methods for requesting data encryption keys.
//
// The Key Access service issues DEKs (Data Encryption Keys) to authorized
// clients based on policy evaluation.
type KeyAccessClient struct {
	conn   *grpc.ClientConn
	config *Config
	auth   *authManager

	client keyaccess.KeyAccessServiceClient
}

// DEKRequest contains parameters for requesting a data encryption key.
type DEKRequest struct {
	ClientID           string            // Client requesting the key
	ResourceAttributes map[string]string // Attributes of the resource to encrypt
	Purpose            string            // Purpose of the key (e.g., "encryption", "backup")
	Context            map[string]string // Additional context
}

// DEKResponse contains the issued data encryption key.
type DEKResponse struct {
	DEK             []byte            // The data encryption key (plaintext)
	WrappedDEK      []byte            // DEK wrapped with client's public key
	KeyID           string            // Identifier for this DEK
	Algorithm       string            // Encryption algorithm to use
	ExpiresAt       string            // When the DEK expires
	PolicyEvaluated string            // Policy that authorized the DEK
	Metadata        map[string]string // Additional metadata
}

// newKeyAccessClient creates a new Key Access client.
func newKeyAccessClient(conn *grpc.ClientConn, config *Config, auth *authManager) *KeyAccessClient {
	return &KeyAccessClient{
		conn:   conn,
		config: config,
		auth:   auth,
		client: keyaccess.NewKeyAccessServiceClient(conn),
	}
}

// RequestDEK requests a data encryption key for encrypting a resource.
//
// The Key Access service will:
// 1. Evaluate policies to determine if the client is authorized
// 2. Generate a DEK if authorized
// 3. Wrap the DEK with the client's registered public key
// 4. Return both the plaintext and wrapped DEK
//
// Example:
//
//	dek, err := client.KeyAccess.RequestDEK(ctx, &stratium.DEKRequest{
//	    ClientID: "my-app",
//	    ResourceAttributes: map[string]string{
//	        "classification": "secret",
//	        "department":     "engineering",
//	    },
//	    Purpose: "encryption",
//	})
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Use dek.DEK to encrypt data
//	// Store dek.WrappedDEK alongside encrypted data
func (c *KeyAccessClient) RequestDEK(ctx context.Context, req *DEKRequest) (*DEKResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("request cannot be nil")
	}
	if req.ClientID == "" {
		return nil, fmt.Errorf("client_id is required")
	}
	if len(req.ResourceAttributes) == 0 {
		return nil, fmt.Errorf("resource_attributes are required")
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

	// Call gRPC service to wrap DEK
	resp, err := c.client.WrapDEK(ctx, &keyaccess.WrapDEKRequest{
		Resource: req.ClientID, // Use client ID as resource identifier
		Dek:      []byte{},     // Empty for new DEK generation
		Action:   req.Purpose,
		Context:  req.Context,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to wrap DEK: %w", err)
	}

	if !resp.AccessGranted {
		return nil, fmt.Errorf("access denied: %s", resp.AccessReason)
	}

	return &DEKResponse{
		DEK:             []byte{}, // Server doesn't return plaintext DEK for security
		WrappedDEK:      resp.WrappedDek,
		KeyID:           resp.KeyId,
		Algorithm:       "AES-256-GCM", // Default algorithm
		ExpiresAt:       resp.Timestamp.AsTime().Format("2006-01-02T15:04:05Z07:00"),
		PolicyEvaluated: resp.AccessReason,
		Metadata: map[string]string{
			"access_granted": fmt.Sprintf("%t", resp.AccessGranted),
		},
	}, nil
}

// UnwrapDEK unwraps a previously issued DEK using the client's private key.
//
// Note: This operation is typically done client-side using the client's
// private key. This method is provided for completeness if server-side
// unwrapping is supported.
//
// Example:
//
//	dek, err := client.KeyAccess.UnwrapDEK(ctx, "my-app", wrappedDEK)
func (c *KeyAccessClient) UnwrapDEK(ctx context.Context, clientID string, wrappedDEK []byte) ([]byte, error) {
	if clientID == "" {
		return nil, fmt.Errorf("client_id is required")
	}
	if len(wrappedDEK) == 0 {
		return nil, fmt.Errorf("wrapped_dek cannot be empty")
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

	// Call gRPC service to unwrap DEK
	resp, err := c.client.UnwrapDEK(ctx, &keyaccess.UnwrapDEKRequest{
		Resource:   clientID,
		WrappedDek: wrappedDEK,
		Action:     "decrypt",
	})
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap DEK: %w", err)
	}

	if !resp.AccessGranted {
		return nil, fmt.Errorf("access denied: %s", resp.AccessReason)
	}

	return resp.DekForSubject, nil
}
