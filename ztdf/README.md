# ZTDF Package

The ZTDF (Zero Trust Data Format) package provides utilities for encrypting and decrypting data with attribute-based access control (ABAC) and policy enforcement.

## Overview

ZTDF is a secure file format that combines:
- **Encryption**: AES-256-GCM encryption with Data Encryption Keys (DEKs)
- **Access Control**: Policy-based access control with attributes
- **Integrity**: Cryptographic integrity verification
- **Policy Binding**: Tamper-proof binding between encryption keys and policies

## Quick Start

```go
package main

import (
    "context"
    "log"

    "github.com/stratiumdata/go-sdk"
    "github.com/stratiumdata/go-sdk/ztdf"
)

func main() {
    // Create Stratium client
    config := &stratium.Config{
        KeyAccessAddress: "localhost:50053",
        // ... other config
    }

    client, err := stratium.NewClient(config)
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()

    // Create ZTDF client
    ztdfClient := ztdf.NewClient(client)

    // Encrypt data
    plaintext := []byte("sensitive data")
    tdo, err := ztdfClient.Wrap(context.Background(), plaintext, &ztdf.WrapOptions{
        Resource: "my-document",
        Attributes: []ztdf.Attribute{
            {
                URI:         "http://example.com/attr/classification/value/secret",
                DisplayName: "Classification: Secret",
                IsDefault:   true,
            },
        },
    })
    if err != nil {
        log.Fatal(err)
    }

    // Save to file
    if err := ztdf.SaveToFile(tdo, "encrypted.ztdf"); err != nil {
        log.Fatal(err)
    }

    // Load from file
    tdo, err = ztdf.LoadFromFile("encrypted.ztdf")
    if err != nil {
        log.Fatal(err)
    }

    // Decrypt data
    decrypted, err := ztdfClient.Unwrap(context.Background(), tdo, &ztdf.UnwrapOptions{
        Resource:        "my-document",
        VerifyIntegrity: true,
        VerifyPolicy:    true,
    })
    if err != nil {
        log.Fatal(err)
    }

    log.Printf("Decrypted: %s", string(decrypted))
}
```

## Core Concepts

### Wrapping (Encryption)

The wrapping process encrypts data and creates a ZTDF:

1. Generates a random 256-bit AES Data Encryption Key (DEK)
2. Encrypts the payload with the DEK using AES-256-GCM
3. Creates a policy with the specified attributes
4. Wraps the DEK using the Key Access Server (enforces policy)
5. Calculates a cryptographic policy binding (HMAC of policy with DEK)
6. Creates a manifest with all metadata
7. Packages manifest and encrypted payload into a ZIP file

### Unwrapping (Decryption)

The unwrapping process decrypts a ZTDF:

1. Validates the manifest structure
2. Unwraps the DEK using the Key Access Server (enforces policy)
3. Verifies the policy binding (ensures policy hasn't been tampered with)
4. Decrypts the payload with the DEK
5. Verifies payload integrity (ensures data hasn't been corrupted)
6. Returns the plaintext

## API Reference

### Client

#### `NewClient(stratiumClient *stratium.Client) *Client`

Creates a new ZTDF client using an existing Stratium SDK client.

#### `Wrap(ctx context.Context, plaintext []byte, opts *WrapOptions) (*TrustedDataObject, error)`

Encrypts plaintext data and creates a ZTDF.

**Options:**
- `Resource`: Resource identifier for ABAC policy evaluation
- `Attributes`: Data attributes for the policy
- `Policy`: Custom policy (optional, will be generated if not provided)
- `IntegrityCheck`: Whether to include integrity checking (default: true)
- `Context`: Additional context for key access

#### `Unwrap(ctx context.Context, tdo *TrustedDataObject, opts *UnwrapOptions) ([]byte, error)`

Decrypts a ZTDF and returns the plaintext.

**Options:**
- `Resource`: Resource identifier for ABAC policy evaluation
- `VerifyIntegrity`: Whether to verify payload integrity (default: true)
- `VerifyPolicy`: Whether to verify policy binding (default: true)
- `Context`: Additional context for key access

#### `WrapFile(ctx context.Context, inputPath, outputPath string, opts *WrapOptions) error`

Encrypts a file and saves it as a ZTDF.

#### `UnwrapFile(ctx context.Context, inputPath, outputPath string, opts *UnwrapOptions) error`

Decrypts a ZTDF file and saves the plaintext.

### Policy Functions

#### `CreatePolicy(keyAccessURL string, attributes []Attribute) *models.ZtdfPolicy`

Creates a ZTDF policy from attributes.

#### `CreateClassificationPolicy(keyAccessURL, classification string) *models.ZtdfPolicy`

Creates a policy with a standard classification level.

```go
policy := ztdf.CreateClassificationPolicy("kas.example.com:50053", "secret")
```

#### `CreateMultiAttributePolicy(keyAccessURL string, attributeValues map[string]string) *models.ZtdfPolicy`

Creates a policy with multiple attributes.

```go
policy := ztdf.CreateMultiAttributePolicy("kas.example.com:50053", map[string]string{
    "classification": "secret",
    "department":     "engineering",
    "project":        "stratium",
})
```

#### `ParsePolicyFromManifest(manifest *models.Manifest) (*models.ZtdfPolicy, error)`

Extracts and parses the policy from a ZTDF manifest.

#### `GetPolicyInfo(tdo *TrustedDataObject) (*PolicyInfo, error)`

Extracts human-readable policy information from a ZTDF.

```go
info, err := ztdf.GetPolicyInfo(tdo)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Policy UUID: %s\n", info.UUID)
for _, attr := range info.DataAttributes {
    fmt.Printf("  - %s: %s\n", attr.DisplayName, attr.Attribute)
}
```

### File Operations

#### `SaveToFile(tdo *TrustedDataObject, outputPath string) error`

Saves a ZTDF to a ZIP file.

#### `LoadFromFile(zipPath string) (*TrustedDataObject, error)`

Loads a ZTDF from a ZIP file.

#### `SaveToBytes(tdo *TrustedDataObject) ([]byte, error)`

Saves a ZTDF to a byte slice (ZIP format).

#### `LoadFromBytes(zipData []byte) (*TrustedDataObject, error)`

Loads a ZTDF from byte data.

#### `GetFileInfo(zipPath string) (*FileInfo, error)`

Extracts metadata about a ZTDF file without fully decrypting it.

```go
info, err := ztdf.GetFileInfo("encrypted.ztdf")
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Encryption: %s\n", info.EncryptionAlg)
fmt.Printf("Encrypted size: %d bytes\n", info.EncryptedSize)
fmt.Printf("Plaintext size: %d bytes\n", info.PlaintextSize)
```

#### `ValidateZTDFFile(zipPath string) error`

Validates the structure of a ZTDF file.

### Crypto Operations

#### `GenerateDEK() ([]byte, error)`

Generates a random 256-bit AES key for data encryption.

#### `EncryptPayload(plaintext, dek []byte) (ciphertext, iv []byte, err error)`

Encrypts plaintext with AES-256-GCM using the provided DEK.

#### `DecryptPayload(ciphertext, dek, iv []byte) ([]byte, error)`

Decrypts ciphertext with AES-256-GCM using the provided DEK and IV.

#### `CalculatePolicyBinding(dek []byte, policyBase64 string) string`

Computes HMAC-SHA256 of the policy using the DEK as the key.

#### `VerifyPolicyBinding(dek []byte, policyBase64 string, expectedHash string) error`

Verifies that the HMAC of the policy matches the expected hash.

#### `CalculatePayloadHash(payload []byte) []byte`

Computes SHA-256 hash of the payload for integrity verification.

#### `VerifyPayloadHash(payload []byte, expectedHash []byte) error`

Verifies that the payload hash matches the expected hash.

## Examples

### Basic Encryption/Decryption

```go
// Encrypt
tdo, err := ztdfClient.Wrap(ctx, plaintext, &ztdf.WrapOptions{
    Resource: "document-123",
})
if err != nil {
    log.Fatal(err)
}

// Save to file
ztdf.SaveToFile(tdo, "encrypted.ztdf")

// Load from file
tdo, err = ztdf.LoadFromFile("encrypted.ztdf")
if err != nil {
    log.Fatal(err)
}

// Decrypt
plaintext, err := ztdfClient.Unwrap(ctx, tdo, &ztdf.UnwrapOptions{
    Resource: "document-123",
})
```

### Custom Policy

```go
// Create custom policy
policy := ztdf.CreateMultiAttributePolicy("localhost:50053", map[string]string{
    "classification": "secret",
    "department":     "engineering",
    "clearance":      "top-secret",
})

// Wrap with custom policy
tdo, err := ztdfClient.Wrap(ctx, plaintext, &ztdf.WrapOptions{
    Resource: "classified-document",
    Policy:   policy,
})
```

### File Operations

```go
// Wrap a file
err := ztdfClient.WrapFile(ctx, "plaintext.txt", "encrypted.ztdf", &ztdf.WrapOptions{
    Resource: "file-123",
    Attributes: []ztdf.Attribute{
        {
            URI:         "http://example.com/attr/classification/value/confidential",
            DisplayName: "Confidential",
            IsDefault:   true,
        },
    },
})

// Unwrap a file
err = ztdfClient.UnwrapFile(ctx, "encrypted.ztdf", "decrypted.txt", &ztdf.UnwrapOptions{
    Resource: "file-123",
})
```

### Inspecting ZTDF Files

```go
// Get file info without decrypting
info, err := ztdf.GetFileInfo("encrypted.ztdf")
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Encryption Algorithm: %s\n", info.EncryptionAlg)
fmt.Printf("Key Access URL: %s\n", info.KeyAccessURL)
fmt.Printf("Plaintext Size: %d bytes\n", info.PlaintextSize)
fmt.Printf("Encrypted Size: %d bytes\n", info.EncryptedSize)

// Get policy info
policyInfo, err := ztdf.GetPolicyInfo(tdo)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Policy UUID: %s\n", policyInfo.UUID)
fmt.Printf("TDF Spec Version: %s\n", policyInfo.TDFSpecVersion)
for _, attr := range policyInfo.DataAttributes {
    fmt.Printf("  %s: %s\n", attr.DisplayName, attr.Attribute)
}
```

### Validation

```go
// Validate ZTDF file structure
if err := ztdf.ValidateZTDFFile("encrypted.ztdf"); err != nil {
    log.Fatal("Invalid ZTDF:", err)
}

// Validate ZTDF in memory
if err := ztdf.ValidateZTDF(tdo); err != nil {
    log.Fatal("Invalid ZTDF:", err)
}

// Validate policy
policy, err := ztdf.ParsePolicyFromManifest(tdo.Manifest)
if err != nil {
    log.Fatal(err)
}

if err := ztdf.ValidatePolicy(policy); err != nil {
    log.Fatal("Invalid policy:", err)
}
```

## Security Considerations

1. **Policy Binding**: The ZTDF format includes a cryptographic binding between the DEK and the policy. This prevents attackers from tampering with the policy without invalidating the encryption.

2. **Integrity Verification**: Always enable integrity verification when unwrapping to detect payload tampering.

3. **Policy Enforcement**: Access control policies are enforced by the Key Access Server during both wrap and unwrap operations.

4. **Key Protection**: DEKs are never stored in plaintext. They are always wrapped by the Key Access Server and can only be unwrapped by authorized subjects.

5. **Secure Deletion**: After encrypting data, securely delete the plaintext DEK from memory.

## ZTDF File Structure

A ZTDF file is a ZIP archive containing:

```
encrypted.ztdf
├── manifest.json      # JSON manifest with encryption metadata
└── 0.payload         # Encrypted payload data
```

### Manifest Structure

The manifest contains:
- **Assertions**: Metadata and handling instructions
- **Encryption Information**: Algorithm, key access objects, policy
- **Integrity Information**: Hashes for integrity verification
- **Payload Reference**: Reference to the encrypted payload

## Error Handling

```go
tdo, err := ztdfClient.Wrap(ctx, plaintext, opts)
if err != nil {
    switch {
    case strings.Contains(err.Error(), "access denied"):
        log.Fatal("Access denied by policy")
    case strings.Contains(err.Error(), "failed to wrap DEK"):
        log.Fatal("Key Access Server error")
    default:
        log.Fatal("Encryption failed:", err)
    }
}

plaintext, err := ztdfClient.Unwrap(ctx, tdo, opts)
if err != nil {
    switch {
    case strings.Contains(err.Error(), "access denied"):
        log.Fatal("Access denied by policy")
    case strings.Contains(err.Error(), "policy verification failed"):
        log.Fatal("Policy has been tampered with")
    case strings.Contains(err.Error(), "integrity verification failed"):
        log.Fatal("Payload has been corrupted")
    default:
        log.Fatal("Decryption failed:", err)
    }
}
```

## Best Practices

1. **Always Use Attributes**: Specify meaningful attributes for access control policies
2. **Enable Verification**: Always enable integrity and policy verification when unwrapping
3. **Resource Naming**: Use consistent, meaningful resource identifiers
4. **Error Handling**: Always check for errors and handle policy/integrity failures appropriately
5. **Secure Storage**: Store ZTDF files securely, as they contain encrypted data
6. **Audit Logging**: Log all wrap/unwrap operations for audit trails

## Advanced Topics

### Custom DEK Generation

For advanced use cases, you can generate your own DEK:

```go
dek, err := ztdf.GenerateDEK()
if err != nil {
    log.Fatal(err)
}

// Use the DEK for encryption
ciphertext, iv, err := ztdf.EncryptPayload(plaintext, dek)
```

### Direct Crypto Operations

For low-level control:

```go
// Generate DEK
dek, _ := ztdf.GenerateDEK()

// Encrypt
ciphertext, iv, _ := ztdf.EncryptPayload(plaintext, dek)

// Calculate policy binding
binding := ztdf.CalculatePolicyBinding(dek, policyBase64)

// Calculate integrity hash
hash := ztdf.CalculatePayloadHash(ciphertext)

// Decrypt
plaintext, _ := ztdf.DecryptPayload(ciphertext, dek, iv)

// Verify policy binding
err := ztdf.VerifyPolicyBinding(dek, policyBase64, binding)

// Verify integrity
err = ztdf.VerifyPayloadHash(ciphertext, hash)
```