package main

import (
	"context"
	"fmt"
	"log"

	"github.com/stratiumdata/stratium-sdk-go"
)

func main() {
	// Configure the Stratium client
	config := &stratium.Config{
		PlatformAddress:   "localhost:50051",
		KeyManagerAddress: "localhost:50052",
		KeyAccessAddress:  "localhost:50053",
		PAPAddress:        "http://localhost:8090",
		OIDC: &stratium.OIDCConfig{
			IssuerURL:    "https://keycloak.example.com/realms/stratium",
			ClientID:     "my-app",
			ClientSecret: "your-client-secret",
		},
	}

	// Create the client
	client, err := stratium.NewClient(config)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	ctx := context.Background()

	// Example 1: Make an authorization decision
	fmt.Println("=== Authorization Decision Example ===")
	decision, err := client.Platform.GetDecision(ctx, &stratium.AuthorizationRequest{
		SubjectAttributes: map[string]string{
			"sub":        "user123",
			"email":      "user@example.com",
			"department": "engineering",
		},
		ResourceAttributes: map[string]string{
			"name": "document-service",
			"type": "service",
		},
		Action: "read",
		Context: map[string]string{
			"ip_address": "192.168.1.100",
		},
	})
	if err != nil {
		log.Printf("Authorization error: %v", err)
	} else {
		fmt.Printf("Decision: %v\n", decision.Decision)
		fmt.Printf("Reason: %s\n", decision.Reason)
		if decision.Decision == stratium.DecisionAllow {
			fmt.Println("✓ Access granted!")
		} else {
			fmt.Println("✗ Access denied!")
		}
	}

	// Example 2: Register a client key
	fmt.Println("\n=== Key Registration Example ===")
	publicKeyPEM := `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
-----END PUBLIC KEY-----`

	key, err := client.KeyManager.RegisterKey(ctx, &stratium.RegisterKeyRequest{
		ClientID:     "my-app",
		PublicKeyPEM: publicKeyPEM,
		KeyType:      stratium.KeyTypeRSA4096,
		Metadata: map[string]string{
			"environment": "production",
		},
	})
	if err != nil {
		log.Printf("Key registration error: %v", err)
	} else {
		fmt.Printf("Key registered: %s\n", key.KeyID)
	}

	// Example 3: Request a DEK for encryption
	fmt.Println("\n=== DEK Request Example ===")
	dek, err := client.KeyAccess.RequestDEK(ctx, &stratium.DEKRequest{
		ClientID: "my-app",
		ResourceAttributes: map[string]string{
			"classification": "secret",
			"department":     "engineering",
		},
		Purpose: "encryption",
	})
	if err != nil {
		log.Printf("DEK request error: %v", err)
	} else {
		fmt.Printf("DEK issued: %s\n", dek.KeyID)
		fmt.Printf("Algorithm: %s\n", dek.Algorithm)
		fmt.Printf("DEK size: %d bytes\n", len(dek.DEK))
		fmt.Printf("Wrapped DEK size: %d bytes\n", len(dek.WrappedDEK))
	}

	// Example 4: Encrypt data
	fmt.Println("\n=== Data Encryption Example ===")
	plaintext := []byte("This is sensitive data")
	encrypted, err := client.KeyManager.EncryptData(ctx, "my-app", key.KeyID, plaintext)
	if err != nil {
		log.Printf("Encryption error: %v", err)
	} else {
		fmt.Printf("Encrypted %d bytes into %d bytes\n", len(plaintext), len(encrypted.Ciphertext))
		fmt.Printf("Wrapped DEK: %d bytes\n", len(encrypted.WrappedDEK))
	}

	// Example 5: Create a policy
	fmt.Println("\n=== Policy Creation Example ===")
	policy, err := client.PAP.CreatePolicy(ctx, &stratium.Policy{
		Name:        "admin-full-access",
		Description: "Administrators have full access to all resources",
		Language:    "OPA",
		PolicyContent: `package authz
default allow = false
allow {
    input.subject.role == "admin"
}`,
		Effect:   "allow",
		Priority: 100,
		Enabled:  true,
	})
	if err != nil {
		log.Printf("Policy creation error: %v", err)
	} else {
		fmt.Printf("Policy created: %s (ID: %s)\n", policy.Name, policy.ID)
	}

	// Example 6: Create an entitlement
	fmt.Println("\n=== Entitlement Creation Example ===")
	entitlement, err := client.PAP.CreateEntitlement(ctx, &stratium.EntitlementCreate{
		Name:        "engineering-docs-read",
		Description: "Engineering team can read documentation",
		SubjectAttributes: map[string]interface{}{
			"department": "engineering",
		},
		ResourceAttributes: map[string]interface{}{
			"type": "document",
		},
		Actions: []string{"read", "list"},
		Enabled: true,
	})
	if err != nil {
		log.Printf("Entitlement creation error: %v", err)
	} else {
		fmt.Printf("Entitlement created: %s (ID: %s)\n", entitlement.Name, entitlement.ID)
	}

	// Example 7: List all policies
	fmt.Println("\n=== List Policies Example ===")
	policies, err := client.PAP.ListPolicies(ctx)
	if err != nil {
		log.Printf("List policies error: %v", err)
	} else {
		fmt.Printf("Found %d policies:\n", len(policies))
		for _, p := range policies {
			fmt.Printf("  - %s (%s): %s\n", p.Name, p.Language, p.Description)
		}
	}

	// Example 8: Check access (convenience method)
	fmt.Println("\n=== Quick Access Check Example ===")
	allowed, err := client.Platform.CheckAccess(ctx, &stratium.AuthorizationRequest{
		SubjectAttributes: map[string]string{
			"sub":  "admin123",
			"role": "admin",
		},
		ResourceAttributes: map[string]string{
			"name": "sensitive-data",
		},
		Action: "delete",
	})
	if err != nil {
		log.Printf("Access check error: %v", err)
	} else {
		if allowed {
			fmt.Println("✓ Admin can delete sensitive data")
		} else {
			fmt.Println("✗ Admin cannot delete sensitive data")
		}
	}

	fmt.Println("\n=== Examples Complete ===")
}
