# Stratium Go SDK

Official Golang SDK for integrating with the Stratium platform.

## Overview

The Stratium SDK provides easy-to-use clients for all Stratium services:

- **Platform Service**: Make authorization decisions based on policies and entitlements
- **Key Manager Service**: Register keys, encrypt/decrypt data
- **Key Access Service**: Request data encryption keys (DEKs)
- **PAP Service**: Manage policies and entitlements

## Installation

```bash
go get github.com/stratiumdata/stratium-sdk-go
```

## Quick Start

```go
package main

import (
    "context"
    "log"

    "github.com/stratiumdata/stratium-sdk-go"
)

func main() {
    // Configure the client
    config := &stratium.Config{
        PlatformAddress:   "localhost:50051",
        KeyManagerAddress: "localhost:50052",
        KeyAccessAddress:  "localhost:50053",
        PAPAddress:        "http://localhost:8090",
        OIDC: &stratium.OIDCConfig{
            IssuerURL:    "https://keycloak.example.com/realms/stratium",
            ClientID:     "my-app",
            ClientSecret: "secret",
        },
    }

    // Create the client
    client, err := stratium.NewClient(config)
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()

    ctx := context.Background()

    // Make an authorization decision
    decision, err := client.Platform.GetDecision(ctx, &stratium.AuthorizationRequest{
        SubjectAttributes: map[string]string{
            "sub":        "user123",
            "department": "engineering",
        },
        ResourceAttributes: map[string]string{
            "name": "document-service",
        },
        Action: "read",
    })
    if err != nil {
        log.Fatal(err)
    }

    if decision.Decision == stratium.DecisionAllow {
        log.Println("Access granted!")
    } else {
        log.Printf("Access denied: %s", decision.Reason)
    }
}
```

## Features

### 🔐 Authorization Decisions

Check if a user/client is authorized to perform an action:

```go
decision, err := client.Platform.GetDecision(ctx, &stratium.AuthorizationRequest{
    SubjectAttributes: map[string]string{
        "sub":   "user123",
        "email": "user@example.com",
        "role":  "developer",
    },
    ResourceAttributes: map[string]string{
        "name": "api-server",
        "type": "service",
    },
    Action: "write",
})
```

### 🔑 Key Management

Register client keys for encryption:

```go
key, err := client.KeyManager.RegisterKey(ctx, &stratium.RegisterKeyRequest{
    ClientID:     "my-app",
    PublicKeyPEM: publicKeyPEM,
    KeyType:      stratium.KeyTypeRSA4096,
})
```

### 🔒 Data Encryption

Encrypt sensitive data:

```go
encrypted, err := client.KeyManager.EncryptData(
    ctx,
    "my-app",
    "key-12345",
    []byte("sensitive data"),
)
```

### 🎫 DEK Requests

Request data encryption keys:

```go
dek, err := client.KeyAccess.RequestDEK(ctx, &stratium.DEKRequest{
    ClientID: "my-app",
    ResourceAttributes: map[string]string{
        "classification": "secret",
        "department":     "engineering",
    },
    Purpose: "encryption",
})

// Use dek.DEK to encrypt data
// Store dek.WrappedDEK alongside encrypted data
```

### 📋 Policy Management

Create and manage policies:

```go
policy, err := client.PAP.CreatePolicy(ctx, &stratium.Policy{
    Name:        "admin-access",
    Description: "Admins have full access",
    Language:    "OPA",
    PolicyContent: `package authz
default allow = false
allow { input.subject.role == "admin" }`,
    Effect:   "allow",
    Priority: 100,
    Enabled:  true,
})
```

### 📝 Entitlement Management

Create and manage entitlements:

```go
entitlement, err := client.PAP.CreateEntitlement(ctx, &stratium.EntitlementCreate{
    Name: "engineering-docs-read",
    SubjectAttributes: map[string]interface{}{
        "department": "engineering",
    },
    ResourceAttributes: map[string]interface{}{
        "type": "document",
    },
    Actions: []string{"read", "list"},
    Enabled: true,
})
```

## Configuration

### Service Addresses

Configure connections to Stratium services:

```go
config := &stratium.Config{
    PlatformAddress:   "platform.example.com:50051",
    KeyManagerAddress: "key-manager.example.com:50052",
    KeyAccessAddress:  "key-access.example.com:50053",
    PAPAddress:        "http://pap.example.com:8090",
}
```

### Authentication

Configure OIDC authentication:

```go
config.OIDC = &stratium.OIDCConfig{
    IssuerURL:    "https://keycloak.example.com/realms/stratium",
    ClientID:     "my-app",
    ClientSecret: "your-client-secret",
    Scopes:       []string{"openid", "profile", "email"},
}
```

The SDK handles token management automatically, including:
- Initial authentication
- Token refresh
- Automatic retry on token expiration

### Timeouts and Retries

```go
config.Timeout = 30 * time.Second  // Request timeout
config.RetryAttempts = 3           // Number of retries on failure
```

### TLS

```go
config.UseTLS = true  // Enable TLS for gRPC connections
```

## Advanced Usage

### Manual Token Management

Get the current authentication token:

```go
token, err := client.GetToken(ctx)
```

Force a token refresh:

```go
err := client.RefreshToken(ctx)
```

### Connection Management

Check if the client is closed:

```go
if client.IsClosed() {
    // Reconnect or handle error
}
```

Close all connections:

```go
client.Close()
```

### Convenience Methods

Check access without full decision response:

```go
allowed, err := client.Platform.CheckAccess(ctx, &stratium.AuthorizationRequest{
    SubjectAttributes: map[string]string{"sub": "user123"},
    ResourceAttributes: map[string]string{"name": "resource"},
    Action: "read",
})

if allowed {
    // Grant access
}
```

## Error Handling

The SDK returns detailed error messages:

```go
decision, err := client.Platform.GetDecision(ctx, req)
if err != nil {
    if strings.Contains(err.Error(), "authentication failed") {
        // Handle auth error
    } else if strings.Contains(err.Error(), "connection refused") {
        // Handle connection error
    } else {
        // Handle other errors
    }
    return err
}
```

## Examples

See the [examples directory](./examples/) for complete usage examples:

- `basic_usage.go` - Comprehensive example showing all SDK features

## API Reference

### Platform Client

- `GetDecision(ctx, req)` - Make an authorization decision
- `GetEntitlements(ctx, subjectAttrs)` - Get entitlements for a subject
- `CheckAccess(ctx, req)` - Convenience method to check if access is allowed

### Key Manager Client

- `RegisterKey(ctx, req)` - Register a client public key
- `GetKey(ctx, req)` - Get a registered key
- `ListKeys(ctx, clientID, includeRevoked)` - List all keys for a client
- `EncryptData(ctx, clientID, keyID, plaintext)` - Encrypt data
- `DecryptData(ctx, req)` - Decrypt data

### Key Access Client

- `RequestDEK(ctx, req)` - Request a data encryption key
- `UnwrapDEK(ctx, clientID, wrappedDEK)` - Unwrap a DEK (if supported)

### PAP Client

#### Policies
- `CreatePolicy(ctx, policy)` - Create a new policy
- `GetPolicy(ctx, policyID)` - Get a policy by ID
- `ListPolicies(ctx)` - List all policies
- `UpdatePolicy(ctx, policy)` - Update a policy
- `DeletePolicy(ctx, policyID)` - Delete a policy

#### Entitlements
- `CreateEntitlement(ctx, entitlement)` - Create an entitlement
- `GetEntitlement(ctx, entitlementID)` - Get an entitlement by ID
- `ListEntitlements(ctx)` - List all entitlements
- `DeleteEntitlement(ctx, entitlementID)` - Delete an entitlement

## Requirements

- Go 1.23 or higher
- Access to Stratium services
- OIDC provider (e.g., Keycloak)

## Security Considerations

- **Secrets**: Never commit client secrets to version control
- **TLS**: Always use TLS in production (`config.UseTLS = true`)
- **Tokens**: The SDK handles token refresh automatically
- **Timeouts**: Set appropriate timeouts for your use case

## Development Status

⚠️ **Note**: This SDK requires protobuf code generation to be complete. Run the following to generate gRPC stubs:

```bash
cd sdk/stratium
make generate-proto
```

## Support

- Documentation: https://docs.stratium.example.com
- Issues: https://github.com/stratiumdata/stratium-sdk-go/issues
- Email: support@stratium.example.com

## License

Copyright © 2025 Stratium Data Platform