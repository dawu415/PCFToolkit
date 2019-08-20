package privatekey

import (
	"fmt"

	"github.com/dawu415/PCFToolkit/cert/certificateRepository/pemDecoder"
	"github.com/dawu415/PCFToolkit/cert/certificateRepository/x509Parser"
)

// PEMPrivateKeyLoaderInterface  defines an interface to Load a PEM Private Key
type PEMPrivateKeyLoaderInterface interface {
	LoadPEMPrivateKey(privateKeylabel, serverCertLabel string, PEMKeyBytes []byte, passphrase string) (PrivateKey, error)
}

// PrivateKey defines a struct holding information and the necessary interfaces relating to a private key
type PrivateKey struct {
	Label           string
	ServerCertLabel string
	PrivateKey      interface{}
	pemDecoder      pemDecoder.PEMDecoderInterface
	x509Parser      x509parser.X509ParserInterface
}

// NewCustomPrivateKey instantiates a new PrivateKey loader with custom decoder and parser interface
func NewCustomPrivateKey(decoder pemDecoder.PEMDecoderInterface, parser x509parser.X509ParserInterface) PEMPrivateKeyLoaderInterface {
	return &PrivateKey{
		pemDecoder: decoder,
		x509Parser: parser,
	}
}

// NewPrivateKey instantiates a new PrivateKey loader interface
func NewPrivateKey() PEMPrivateKeyLoaderInterface {
	return &PrivateKey{
		pemDecoder: pemDecoder.NewPEMDecoder(),
		x509Parser: x509parser.Newx509Parser(),
	}
}

// LoadPEMPrivateKey will load a PEM private key give the read in PEMKeyBytes and decrypted it with a passphrase
// The privatekeyLabel provides a means to easily identify private keys.
// If a passphrase is provided, the private key must be encrypted, if it is not, an error will be returned.
func (key *PrivateKey) LoadPEMPrivateKey(privateKeylabel, serverCertLabel string, PEMKeyBytes []byte, passphrase string) (PrivateKey, error) {
	var err error
	var decodedPrivateKeyBytes []byte
	var x509ParsedPrivateKey interface{}
	var privateKey PrivateKey

	// Assume that there is only 1 private key in the file
	privateKeyBlock, _ := key.pemDecoder.Decode(PEMKeyBytes)
	if privateKeyBlock != nil {
		if decodedPrivateKeyBytes, err = key.pemDecoder.DecryptPEM(privateKeyBlock, passphrase, privateKeylabel); err == nil {
			if x509ParsedPrivateKey, err = key.x509Parser.ParsePrivateKey(decodedPrivateKeyBytes); err == nil {
				privateKey = PrivateKey{
					Label:           privateKeylabel,
					ServerCertLabel: serverCertLabel,
					PrivateKey:      x509ParsedPrivateKey,
				}
			}
		}
	} else {
		err = fmt.Errorf("Failed to decode a private key PEM block. Check the private key file input content")
	}

	return privateKey, err
}
