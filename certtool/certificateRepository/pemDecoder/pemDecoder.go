package pemDecoder

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// PEMDecoderInterface describes the PEM interface to decode and decrypt PEM blocks
type PEMDecoderInterface interface {
	Decode(data []byte) (p *pem.Block, remainder []byte)
	DecryptPEM(privateKeyBlock *pem.Block, passphrase, privateKeyLabel string) ([]byte, error)
}

// PEMData holds data relating to the PEM. This is currently empty
type PEMData struct {
}

// NewPEMDecoder returns a PEMDecoderInterface
func NewPEMDecoder() PEMDecoderInterface {
	return &PEMData{}
}

// Decode decodes PEM encoded certificate/private key
func (pd *PEMData) Decode(data []byte) (p *pem.Block, remainder []byte) {
	return pem.Decode(data)
}

// DecryptPEM decrypts a private key given its passphrase. If passphrase is specified by there is no encryption,
// this method will fail.  privateKeyLabel sets a tag for the private key for easy identification
func (pd *PEMData) DecryptPEM(privateKeyBlock *pem.Block, passphrase, privateKeyLabel string) ([]byte, error) {
	var err error
	var decryptedPrivateKeyBytes = privateKeyBlock.Bytes
	if x509.IsEncryptedPEMBlock(privateKeyBlock) {
		decryptedPrivateKeyBytes, err = x509.DecryptPEMBlock(privateKeyBlock, []byte(passphrase))
	} else {
		if len(passphrase) > 0 {
			err = fmt.Errorf("Passphrase for private key %s was provided but private key PEM does not appear to be encrypted", privateKeyLabel)
		}
	}

	return decryptedPrivateKeyBytes, err
}
