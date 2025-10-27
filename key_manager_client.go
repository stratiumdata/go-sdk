package stratium

import (
	"context"
	"fmt"
	"time"

	keymanager "github.com/stratiumdata/go-sdk/gen/services/key-manager"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// KeyManagerClient provides methods for interacting with the Key Manager service.
//
// The Key Manager service handles:
//   - Client key registration and lifecycle management
//   - Data encryption key (DEK) generation and wrapping
//   - Key integrity verification
type KeyManagerClient struct {
	conn   *grpc.ClientConn
	config *Config
	auth   *authManager
	client keymanager.KeyManagerServiceClient
}

// KeyType represents the type of cryptographic key.
type KeyType int32

const (
	KeyTypeRSA2048   KeyType = 0
	KeyTypeRSA3072   KeyType = 1
	KeyTypeRSA4096   KeyType = 2
	KeyTypeECC256    KeyType = 3
	KeyTypeECC384    KeyType = 4
	KeyTypeECC521    KeyType = 5
	KeyTypeKyber512  KeyType = 6
	KeyTypeKyber768  KeyType = 7
	KeyTypeKyber1024 KeyType = 8
)

// ClientKey represents a registered client public key.
type ClientKey struct {
	KeyID        string
	ClientID     string
	KeyType      KeyType
	PublicKeyPEM string
	Status       string
	CreatedAt    string
	ExpiresAt    string
	Metadata     map[string]string
}

// RegisterKeyRequest contains the parameters for registering a client key.
type RegisterKeyRequest struct {
	ClientID     string            // Client identifier
	PublicKeyPEM string            // PEM-encoded public key
	KeyType      KeyType           // Type of key (RSA, ECC, Kyber)
	ExpiresAt    string            // Optional expiration time (RFC3339 format)
	Metadata     map[string]string // Optional metadata
}

// GetKeyRequest contains the parameters for retrieving a client key.
type GetKeyRequest struct {
	ClientID string // Client identifier
	KeyID    string // Key identifier
}

// EncryptionResult contains the result of data encryption.
type EncryptionResult struct {
	Ciphertext    []byte // Encrypted data
	WrappedDEK    []byte // Wrapped data encryption key
	EncryptionAlg string // Algorithm used for encryption
}

// DecryptionRequest contains the parameters for data decryption.
type DecryptionRequest struct {
	ClientID      string // Client identifier
	KeyID         string // Key identifier used for encryption
	Ciphertext    []byte // Encrypted data
	WrappedDEK    []byte // Wrapped data encryption key
	EncryptionAlg string // Algorithm used for encryption
}

// newKeyManagerClient creates a new Key Manager client.
func newKeyManagerClient(conn *grpc.ClientConn, config *Config, auth *authManager) *KeyManagerClient {
	return &KeyManagerClient{
		conn:   conn,
		config: config,
		auth:   auth,
		client: keymanager.NewKeyManagerServiceClient(conn),
	}
}

// RegisterKey registers a new client public key with the Key Manager.
//
// This should be called once per client to register their public key for
// data encryption key (DEK) wrapping.
//
// Example:
//
//	key, err := client.KeyManager.RegisterKey(ctx, &stratium.RegisterKeyRequest{
//	    ClientID:     "my-app",
//	    PublicKeyPEM: publicKeyPEM,
//	    KeyType:      stratium.KeyTypeRSA4096,
//	})
func (c *KeyManagerClient) RegisterKey(ctx context.Context, req *RegisterKeyRequest) (*ClientKey, error) {
	if req == nil {
		return nil, fmt.Errorf("request cannot be nil")
	}
	if req.ClientID == "" {
		return nil, fmt.Errorf("client_id is required")
	}
	if req.PublicKeyPEM == "" {
		return nil, fmt.Errorf("public_key_pem is required")
	}

	// Get authentication token
	token := ""
	if c.auth != nil {
		var err error
		token, err = c.auth.GetToken(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get auth token: %w", err)
		}
	}

	// Add timeout and auth context
	ctx, cancel := c.config.contextWithTimeout(ctx)
	defer cancel()
	ctx = contextWithAuth(ctx, token)

	// Parse expiration time if provided
	var expiresAt *timestamppb.Timestamp
	if req.ExpiresAt != "" {
		t, err := time.Parse(time.RFC3339, req.ExpiresAt)
		if err != nil {
			return nil, fmt.Errorf("invalid expires_at format: %w", err)
		}
		expiresAt = timestamppb.New(t)
	}

	// Call gRPC service
	resp, err := c.client.RegisterClientKey(ctx, &keymanager.RegisterClientKeyRequest{
		ClientId:     req.ClientID,
		PublicKeyPem: req.PublicKeyPEM,
		KeyType:      keymanager.KeyType(req.KeyType),
		ExpiresAt:    expiresAt,
		Metadata:     req.Metadata,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to register key: %w", err)
	}

	if !resp.Success {
		return nil, fmt.Errorf("key registration failed: %s", resp.ErrorMessage)
	}

	return &ClientKey{
		KeyID:        resp.Key.KeyId,
		ClientID:     resp.Key.ClientId,
		KeyType:      KeyType(resp.Key.KeyType),
		PublicKeyPEM: resp.Key.PublicKeyPem,
		Status:       resp.Key.Status.String(),
		CreatedAt:    resp.Key.CreatedAt.AsTime().Format(time.RFC3339),
		ExpiresAt:    formatTimestamp(resp.Key.ExpiresAt),
		Metadata:     resp.Key.Metadata,
	}, nil
}

// GetKey retrieves a registered client key by ID.
//
// Example:
//
//	key, err := client.KeyManager.GetKey(ctx, &stratium.GetKeyRequest{
//	    ClientID: "my-app",
//	    KeyID:    "key-12345",
//	})
func (c *KeyManagerClient) GetKey(ctx context.Context, req *GetKeyRequest) (*ClientKey, error) {
	if req == nil {
		return nil, fmt.Errorf("request cannot be nil")
	}
	if req.ClientID == "" {
		return nil, fmt.Errorf("client_id is required")
	}
	if req.KeyID == "" {
		return nil, fmt.Errorf("key_id is required")
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

	// Call gRPC service
	resp, err := c.client.GetClientKey(ctx, &keymanager.GetClientKeyRequest{
		ClientId: req.ClientID,
		KeyId:    req.KeyID,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get key: %w", err)
	}

	if !resp.Found {
		return nil, fmt.Errorf("key not found: %s", resp.ErrorMessage)
	}

	return &ClientKey{
		KeyID:        resp.Key.KeyId,
		ClientID:     resp.Key.ClientId,
		KeyType:      KeyType(resp.Key.KeyType),
		PublicKeyPEM: resp.Key.PublicKeyPem,
		Status:       resp.Key.Status.String(),
		CreatedAt:    resp.Key.CreatedAt.AsTime().Format(time.RFC3339),
		ExpiresAt:    formatTimestamp(resp.Key.ExpiresAt),
		Metadata:     resp.Key.Metadata,
	}, nil
}

// EncryptData encrypts data using a generated DEK, wrapped with the client's public key.
//
// The Key Manager generates a data encryption key (DEK), encrypts the data,
// and wraps the DEK with the client's public key. The client can then unwrap
// the DEK with their private key to decrypt the data.
//
// Example:
//
//	result, err := client.KeyManager.EncryptData(ctx, "my-app", "key-12345", []byte("sensitive data"))
//	if err != nil {
//	    log.Fatal(err)
//	}
//	// Store result.Ciphertext and result.WrappedDEK
func (c *KeyManagerClient) EncryptData(ctx context.Context, clientID, keyID string, plaintext []byte) (*EncryptionResult, error) {
	if clientID == "" {
		return nil, fmt.Errorf("client_id is required")
	}
	if keyID == "" {
		return nil, fmt.Errorf("key_id is required")
	}
	if len(plaintext) == 0 {
		return nil, fmt.Errorf("plaintext cannot be empty")
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
	// resp, err := c.client.EncryptData(ctx, &keymanager.EncryptDataRequest{...})

	return nil, fmt.Errorf("not implemented - protobuf stubs need to be generated")
}

// DecryptData decrypts data using the wrapped DEK.
//
// The client must first unwrap the DEK using their private key, then call
// this method to decrypt the data.
//
// Example:
//
//	plaintext, err := client.KeyManager.DecryptData(ctx, &stratium.DecryptionRequest{
//	    ClientID:      "my-app",
//	    KeyID:         "key-12345",
//	    Ciphertext:    ciphertext,
//	    WrappedDEK:    wrappedDEK,
//	    EncryptionAlg: "AES-256-GCM",
//	})
func (c *KeyManagerClient) DecryptData(ctx context.Context, req *DecryptionRequest) ([]byte, error) {
	if req == nil {
		return nil, fmt.Errorf("request cannot be nil")
	}
	if req.ClientID == "" {
		return nil, fmt.Errorf("client_id is required")
	}
	if req.KeyID == "" {
		return nil, fmt.Errorf("key_id is required")
	}
	if len(req.Ciphertext) == 0 {
		return nil, fmt.Errorf("ciphertext cannot be empty")
	}
	if len(req.WrappedDEK) == 0 {
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

	// TODO: Call gRPC service
	// resp, err := c.client.DecryptData(ctx, &keymanager.DecryptDataRequest{...})

	return nil, fmt.Errorf("not implemented - protobuf stubs need to be generated")
}

// ListKeys lists all registered keys for a client.
//
// Example:
//
//	keys, err := client.KeyManager.ListKeys(ctx, "my-app", false)
func (c *KeyManagerClient) ListKeys(ctx context.Context, clientID string, includeRevoked bool) ([]*ClientKey, error) {
	if clientID == "" {
		return nil, fmt.Errorf("client_id is required")
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

	// Call gRPC service
	resp, err := c.client.ListClientKeys(ctx, &keymanager.ListClientKeysRequest{
		ClientId:       clientID,
		IncludeRevoked: includeRevoked,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list keys: %w", err)
	}

	keys := make([]*ClientKey, len(resp.Keys))
	for i, key := range resp.Keys {
		keys[i] = &ClientKey{
			KeyID:        key.KeyId,
			ClientID:     key.ClientId,
			KeyType:      KeyType(key.KeyType),
			PublicKeyPEM: key.PublicKeyPem,
			Status:       key.Status.String(),
			CreatedAt:    key.CreatedAt.AsTime().Format(time.RFC3339),
			ExpiresAt:    formatTimestamp(key.ExpiresAt),
			Metadata:     key.Metadata,
		}
	}

	return keys, nil
}

// formatTimestamp formats a protobuf timestamp to RFC3339 string, or returns empty if nil
func formatTimestamp(ts *timestamppb.Timestamp) string {
	if ts == nil {
		return ""
	}
	return ts.AsTime().Format(time.RFC3339)
}
