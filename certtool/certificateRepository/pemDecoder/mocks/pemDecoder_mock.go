package pemDecoder_mock

import (
	"encoding/pem"
	"fmt"
)

// PEMDataMock describes the control data that is used to change the beheviour of the mock
type PEMDataMock struct {
	PEMDecodeFailed     bool
	KeyDecryptionFailed bool
	KeyIsEncrypted      bool
}

// NewPEMDecoderMock returns mock PemDocoder
func NewPEMDecoderMock() *PEMDataMock {
	return &PEMDataMock{}
}

// Decode decodes PEM encoded certificate/private key
func (pd *PEMDataMock) Decode(data []byte) (p *pem.Block, remainder []byte) {
	// If decode fails, then we should behave in the same way as a real PEM decoder
	// It will return a nil pem Block and put the rest of the data in remainder
	if pd.PEMDecodeFailed {
		p = nil
		remainder = data
	} else {
		p = &pem.Block{}
		p.Bytes = data
		remainder = nil
	}

	return p, remainder
}

// DecryptPEM decrypts a private key given its passphrase. If passphrase is specified by there is no encryption,
// this method will fail.  privateKeyLabel sets a tag for the private key for easy identification
func (pd *PEMDataMock) DecryptPEM(privateKeyBlock *pem.Block, passphrase, privateKeyLabel string) ([]byte, error) {
	var decryptedPEM []byte
	var err error

	if pd.KeyIsEncrypted {
		if pd.KeyDecryptionFailed {
			decryptedPEM = nil
			err = fmt.Errorf("keyDecryptionFailed was set to TRUE")
		} else {
			decryptedPEM = append(privateKeyBlock.Bytes, []byte("_decrypted_with_"+passphrase)...)
		}
	} else {
		if len(passphrase) > 0 {
			err = fmt.Errorf("keyIsEncrypted was FALSE but passphrase was passed in")
		} else {
			decryptedPEM = privateKeyBlock.Bytes
		}
	}
	return decryptedPEM, err
}
