package sign

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/theupdateframework/go-tuf/encrypted"
	"golang.org/x/term"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

const CosignPrivateKeyPemType = "ENCRYPTED COSIGN PRIVATE KEY"

func SignIdentity(keyPath string, identity string) (string, error) {
	key, err := readPrivateKey(keyPath)
	if err != nil {
		return "", err
	}
	password, err := readPassword()
	if err != nil {
		return "", err
	}
	privateKey, err := loadPrivateKey(key, password, identity)
	if err != nil {
		return "", err
	}
	return privateKey, nil
}

func readPassword() ([]byte, error) {
	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) != 0 {
		fmt.Fprint(os.Stderr, "Enter password for private key: ")
		pw, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return nil, err
		}
		return pw, nil
	} else {
		return io.ReadAll(os.Stdin)
	}
}

func readPrivateKey(path string) ([]byte, error) {
	var raw []byte
	var err error
	raw, err = os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	return raw, nil
}

func loadPrivateKey(key []byte, password []byte, identity string) (string, error) {
	decodedKey, _ := pem.Decode(key)
	if decodedKey == nil {
		return "", errors.New("invalid pem block")
	}
	if decodedKey.Type != CosignPrivateKeyPemType {
		return "", fmt.Errorf("unsupported pem type: %s", decodedKey.Type)
	}
	unencryptedKey, err := encrypted.Decrypt(decodedKey.Bytes, password)
	if err != nil {
		return "", fmt.Errorf("decrypt: %w", err)
	}

	parsedKey, err := x509.ParsePKCS8PrivateKey(unencryptedKey)
	if err != nil {
		return "", fmt.Errorf("parsing private key: %w", err)
	}

	privateKey := parsedKey.(*ecdsa.PrivateKey)
	sig, err := ecdsa.SignASN1(rand.Reader, privateKey, []byte(identity))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sig), nil

}