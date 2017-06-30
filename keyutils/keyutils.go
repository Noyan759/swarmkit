package keyutils

import (
	"crypto"
	cryptorand "crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"

	"github.com/cloudflare/cfssl/helpers"
	"github.com/docker/swarmkit/pkcs8"
)

const ERROR_UNSUPPORTED_KEY = "Unsupported key format"
const FIPSEnvVar = "GOFIPS"

func FIPSEnabled() bool {
	return os.Getenv(FIPSEnvVar) != ""
}

func isPKCS8(pemBytes []byte) bool {
	if _, err := x509.ParsePKCS8PrivateKey(pemBytes); err == nil {
		return true
	}

	return pkcs8.IsEncryptedPEMBlock(&pem.Block{
		Type:    "PRIVATE KEY",
		Headers: nil,
		Bytes:   pemBytes,
	})
}

func ParsePrivateKeyPEMWithPassword(pemBytes, password []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(pemBytes)
	if isPKCS8(block.Bytes) {
		return pkcs8.ParsePrivateKeyPEMWithPassword(pemBytes, password)
	} else if FIPSEnabled() {
		panic(ERROR_UNSUPPORTED_KEY)
	}

	return helpers.ParsePrivateKeyPEMWithPassword(pemBytes, password)
}

func IsEncryptedPEMBlock(block *pem.Block) bool {
	if isPKCS8(block.Bytes) {
		return pkcs8.IsEncryptedPEMBlock(block)
	} else if FIPSEnabled() {
		panic(ERROR_UNSUPPORTED_KEY)
	}

	return x509.IsEncryptedPEMBlock(block)
}

func EncryptPEMBlock(data, password []byte) (*pem.Block, error) {
	if isPKCS8(data) {
		return pkcs8.EncryptPEMBlock(data, password)
	} else if FIPSEnabled() {
		panic(ERROR_UNSUPPORTED_KEY)
	}

	cipherType := x509.PEMCipherAES256
	return x509.EncryptPEMBlock(cryptorand.Reader,
		"EC PRIVATE KEY",
		data,
		password,
		cipherType)
}

func DecryptPEMBlock(block *pem.Block, password []byte) ([]byte, error) {
	if isPKCS8(block.Bytes) {
		return pkcs8.DecryptPEMBlock(block, password)
	} else if FIPSEnabled() {
		panic(ERROR_UNSUPPORTED_KEY)
	}

	return x509.DecryptPEMBlock(block, password)
}
