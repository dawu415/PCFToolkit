package privatekey_mock

import (
	"fmt"

	"github.com/dawu415/PCFToolkit/certtool/certificateRepository/privatekey"
)

// PrivateKeyMock defines a struct holding information and the necessary interfaces relating to a private key
type PrivateKeyMock struct {
	LoadPEMPrivateKeyFailed bool
}

// NewPrivateKeyMock instantiates a new PrivateKey loader interface
func NewPrivateKeyMock() *PrivateKeyMock {
	return &PrivateKeyMock{}
}

// LoadPEMPrivateKey will load a PEM private key give the read in PEMKeyBytes and decrypted it with a passphrase
func (key *PrivateKeyMock) LoadPEMPrivateKey(privateKeylabel, serverCertLabel string, PEMKeyBytes []byte, passphrase string) (privatekey.PrivateKey, error) {
	var err error

	if key.LoadPEMPrivateKeyFailed {
		err = fmt.Errorf("LoadPEMPrivateKeyFailed was set to TRUE")
	}

	return privatekey.PrivateKey{
		Label:           privateKeylabel,
		ServerCertLabel: serverCertLabel,
		PrivateKey:      append(PEMKeyBytes, []byte(passphrase)...),
	}, err
}
