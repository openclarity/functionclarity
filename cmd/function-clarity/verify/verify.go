package verify

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"github.com/openclarity/function-clarity/pkg/integrity"
)

import (
	"errors"
)

const PublicKeyPEMType = "PUBLIC KEY"

func Verify(publicKeyPath string, signature string, identity string) error {
	fmt.Printf("Verification for code identity: %s started\n", identity)
	fmt.Printf("Signed identity: %s\n", signature)

	publicKey, err := loadPublicKey(publicKeyPath)
	if err != nil {
		return err
	}

	err = verifySignature(signature, publicKey, identity)
	if err != nil {
		return err
	}
	return nil
}

func verifySignature(signature string, publicKey *ecdsa.PublicKey, identity string) error {
	decodedSig, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("Signature decoding failed: %s", signature)
	}
	hash := []byte(identity)
	if !ecdsa.VerifyASN1(publicKey, hash[:], decodedSig) {
		return errors.New("Signature verification failed")
	}
	fmt.Printf("Signature verification completed successfully")
	return nil
}

func loadPublicKey(publicKeyPath string) (*ecdsa.PublicKey, error) {
	key, err := integrity.ReadFile(publicKeyPath)
	if err != nil {
		//return "", err
	}
	decodedKey, _ := pem.Decode(key)
	emptyKey := &ecdsa.PublicKey{}
	if decodedKey == nil {
		return emptyKey, errors.New("Public key decoding failed")
	}

	if decodedKey.Type != PublicKeyPEMType {
		return emptyKey, fmt.Errorf("unknown Public key PEM file type: %v. Are you passing the correct public key?", decodedKey.Type)
	}

	parsedKey, err := x509.ParsePKIXPublicKey(decodedKey.Bytes)
	if err != nil {
		return emptyKey, fmt.Errorf("parsing public key: %w", err)
	}
	fmt.Printf("\nPublic key for verification loaded successfully: \n%s\n", string(key[:]))
	return parsedKey.(*ecdsa.PublicKey), nil
}
