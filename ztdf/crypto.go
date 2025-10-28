package ztdf

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// GenerateDEK generates a random 256-bit AES key for data encryption.
//
// Example:
//
//	dek, err := ztdf.GenerateDEK()
//	if err != nil {
//	    log.Fatal(err)
//	}
func GenerateDEK() ([]byte, error) {
	dek := make([]byte, AESKeySize) // AES-256 (32 bytes)
	if _, err := rand.Read(dek); err != nil {
		return nil, fmt.Errorf("failed to generate DEK: %w", err)
	}
	return dek, nil
}

// EncryptPayload encrypts plaintext with AES-256-GCM using the provided DEK.
// Returns the ciphertext and initialization vector (IV).
//
// Example:
//
//	dek, _ := ztdf.GenerateDEK()
//	ciphertext, iv, err := ztdf.EncryptPayload(plaintext, dek)
//	if err != nil {
//	    log.Fatal(err)
//	}
func EncryptPayload(plaintext, dek []byte) (ciphertext, iv []byte, err error) {
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create GCM mode: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext = gcm.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nonce, nil
}

// DecryptPayload decrypts ciphertext with AES-256-GCM using the provided DEK and IV.
//
// Example:
//
//	plaintext, err := ztdf.DecryptPayload(ciphertext, dek, iv)
//	if err != nil {
//	    log.Fatal(err)
//	}
func DecryptPayload(ciphertext, dek, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM mode: %w", err)
	}

	plaintext, err := gcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

// EncryptDEKWithPublicKey encrypts a DEK using RSA-OAEP with SHA-256.
// Used to encrypt the DEK with the client's public key.
//
// Example:
//
//	encryptedDEK, err := ztdf.EncryptDEKWithPublicKey(publicKey, dek)
//	if err != nil {
//	    log.Fatal(err)
//	}
func EncryptDEKWithPublicKey(publicKey *rsa.PublicKey, dek []byte) ([]byte, error) {
	encryptedDEK, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, dek, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt DEK with public key: %w", err)
	}
	return encryptedDEK, nil
}

// DecryptDEKWithPrivateKey decrypts a DEK using RSA-OAEP with SHA-256.
// Used to decrypt the DEK with the client's private key.
//
// Example:
//
//	dek, err := ztdf.DecryptDEKWithPrivateKey(privateKey, encryptedDEK)
//	if err != nil {
//	    log.Fatal(err)
//	}
func DecryptDEKWithPrivateKey(privateKey *rsa.PrivateKey, encryptedDEK []byte) ([]byte, error) {
	dek, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, encryptedDEK, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt DEK with private key: %w", err)
	}
	return dek, nil
}

// CalculatePolicyBinding computes HMAC-SHA256 of the policy using the DEK as the key.
// This creates a cryptographic binding between the DEK and the policy to prevent tampering.
//
// Example:
//
//	binding := ztdf.CalculatePolicyBinding(dek, policyBase64)
func CalculatePolicyBinding(dek []byte, policyBase64 string) string {
	h := hmac.New(sha256.New, dek)
	h.Write([]byte(policyBase64))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// VerifyPolicyBinding verifies that the HMAC of the policy matches the expected hash.
// Returns an error if the binding verification fails.
//
// Example:
//
//	if err := ztdf.VerifyPolicyBinding(dek, policyBase64, expectedHash); err != nil {
//	    log.Fatal("Policy has been tampered with!")
//	}
func VerifyPolicyBinding(dek []byte, policyBase64 string, expectedHash string) error {
	calculatedHash := CalculatePolicyBinding(dek, policyBase64)
	if calculatedHash != expectedHash {
		return fmt.Errorf("policy binding verification failed: HMAC mismatch")
	}
	return nil
}

// CalculatePayloadHash computes SHA-256 hash of the payload for integrity verification.
//
// Example:
//
//	hash := ztdf.CalculatePayloadHash(payload)
func CalculatePayloadHash(payload []byte) []byte {
	hash := sha256.Sum256(payload)
	return hash[:]
}

// VerifyPayloadHash verifies that the payload hash matches the expected hash.
// Returns an error if the integrity check fails.
//
// Example:
//
//	if err := ztdf.VerifyPayloadHash(payload, expectedHash); err != nil {
//	    log.Fatal("Payload has been tampered with!")
//	}
func VerifyPayloadHash(payload []byte, expectedHash []byte) error {
	actualHash := CalculatePayloadHash(payload)
	if !hmac.Equal(actualHash, expectedHash) {
		return fmt.Errorf("payload integrity verification failed: hash mismatch")
	}
	return nil
}