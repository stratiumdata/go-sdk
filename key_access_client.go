package stratium

import (
	"context"
	"fmt"

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

	// TODO: Add generated proto client when available
	// client keyaccess.KeyAccessServiceClient
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
		// client: keyaccess.NewKeyAccessServiceClient(conn),
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

	// TODO: Call gRPC service
	// resp, err := c.client.RequestDEK(ctx, &keyaccess.RequestDEKRequest{...})

	return nil, fmt.Errorf("not implemented - protobuf stubs need to be generated")
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

	// TODO: Call gRPC service if server-side unwrapping is supported
	// resp, err := c.client.UnwrapDEK(ctx, &keyaccess.UnwrapDEKRequest{...})

	return nil, fmt.Errorf("not implemented - protobuf stubs need to be generated")
}
