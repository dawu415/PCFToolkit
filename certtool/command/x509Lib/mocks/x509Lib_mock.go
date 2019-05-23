package x509libmock

import (
	"fmt"

	"github.com/dawu415/PCFToolkit/certtool/certificateRepository/certificate"
)

// X509LibMock defines a mock wrapper to the crypto/x509 module
type X509LibMock struct {
	TrustChainExist                      bool
	SystemCerts                          []certificate.Certificate
	FailedToGetPartialSystemCertificates bool
}

// NewX509LibMock generates a new X509LibMock struct
func NewX509LibMock() *X509LibMock {
	return &X509LibMock{}
}

// TrustChainExistOn is a mock function controlled by the inputs defined in the x509LibMock struct
func (x *X509LibMock) TrustChainExistOn(serverCert certificate.Certificate, rootCerts, intermediateCerts []certificate.Certificate) bool {
	return x.TrustChainExist
}

// GetPartialSystemCertificates returns an array of partial system root certificates from the system store.
// It is partial because we only return certificates containing the issuer and subject, which should be identical.
func (x *X509LibMock) GetPartialSystemCertificates() ([]certificate.Certificate, error) {

	var err error
	if x.FailedToGetPartialSystemCertificates {
		err = fmt.Errorf("FailedToGetPartialSystemCertificates was set to TRUE")
	}
	return x.SystemCerts, err
}
