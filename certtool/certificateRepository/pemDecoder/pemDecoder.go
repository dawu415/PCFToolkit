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

/*
// Encrypted PKCS8
type prfParam struct {
	IdPRF     asn1.ObjectIdentifier
	NullParam asn1.RawValue
}

type pbkdf2Params struct {
	Salt           []byte
	IterationCount int
	PrfParam       prfParam `asn1:"optional"`
}

type pbkdf2Algorithms struct {
	IdPBKDF2     asn1.ObjectIdentifier
	PBKDF2Params pbkdf2Params
}

type pbkdf2Encs struct {
	EncryAlgo asn1.ObjectIdentifier
	IV        []byte
}

type pbes2Params struct {
	KeyDerivationFunc pbkdf2Algorithms
	EncryptionScheme  pbkdf2Encs
}

type pbes2Algorithms struct {
	IdPBES2     asn1.ObjectIdentifier
	PBES2Params pbes2Params
}

type encryptedPrivateKeyInfo struct {
	EncryptionAlgorithm pbes2Algorithms
	EncryptedData       []byte
}*/

// DecryptPEM decrypts a private key given its passphrase. If passphrase is specified but there is no encryption,
// or that there is no specified encryption via the DEK-Info header, this method will fail.
// privateKeyLabel sets a tag for the private key for easy identification
func (pd *PEMData) DecryptPEM(privateKeyBlock *pem.Block, passphrase, privateKeyLabel string) ([]byte, error) {
	var err error
	var decryptedPrivateKeyBytes = privateKeyBlock.Bytes
	/*
		var (
			//oidPKCS5PBKDF2    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
			//oidPBES2          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
			oidAES256CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
			oidAES128CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
			//oidHMACWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
			oidDESEDE3CBC = asn1.ObjectIdentifier{1, 2, 840, 113549, 3, 7}
		)

		///	privateKeyBlock.Headers["DEK-Info"]
		var privKey encryptedPrivateKeyInfo
		if _, err := asn1.Unmarshal(decryptedPrivateKeyBytes, &privKey); err != nil {
			return nil, errors.New("pkcs8: only PKCS #5 v2.0 supported")
		}

		encParam := privKey.EncryptionAlgorithm.PBES2Params.EncryptionScheme
		//kdfParam := privKey.EncryptionAlgorithm.PBES2Params.KeyDerivationFunc.PBKDF2Params

		iv := encParam.IV
		privateKeyBlock.Headers["Proc-Type"] = "4,ENCRYPTED"
		switch {
		case encParam.EncryAlgo.Equal(oidAES128CBC):
			privateKeyBlock.Headers["DEK-Info"] = "AES-128-CBC," + strings.ToUpper(hex.EncodeToString(iv))
		case encParam.EncryAlgo.Equal(oidAES256CBC):
			privateKeyBlock.Headers["DEK-Info"] = "AES-256-CBC," + strings.ToUpper(hex.EncodeToString(iv))
		case encParam.EncryAlgo.Equal(oidDESEDE3CBC):
			privateKeyBlock.Headers["DEK-Info"] = "DES-EDE3-CBC," + strings.ToUpper(hex.EncodeToString(iv))
		default:
			return nil, errors.New("pkcs8: only AES-256-CBC, AES-128-CBC and DES-EDE3-CBC are supported")
		}
	*/
	fmt.Println(privateKeyBlock.Headers["DEK-Info"])
	fmt.Println(len(privateKeyBlock.Bytes))
	if x509.IsEncryptedPEMBlock(privateKeyBlock) {
		fmt.Println("Decrypting!")
		decryptedPrivateKeyBytes, err = x509.DecryptPEMBlock(privateKeyBlock, []byte(passphrase))
	} else {
		if len(passphrase) > 0 {
			err = fmt.Errorf("Passphrase for private key %s was provided but private key PEM does not appear to be encrypted, the format is not supported or that the DEK-Info was not available.", privateKeyLabel)
		}
	}

	return decryptedPrivateKeyBytes, err
}
