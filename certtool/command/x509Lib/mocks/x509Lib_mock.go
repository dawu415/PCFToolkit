package x509libmock

import "github.com/dawu415/PCFToolkit/certtool/certificateRepository/certificate"

// X509LibMock defines a mock wrapper to the crypto/x509 module
type X509LibMock struct {
	TrustChainExist bool
}

// NewX509LibMock generates a new X509LibMock struct
func NewX509LibMock() *X509LibMock {
	return &X509LibMock{}
}

// TrustChainExistOn is a mock function controlled by the inputs defined in the x509LibMock struct
func (x *X509LibMock) TrustChainExistOn(serverCert certificate.Certificate, rootCerts, intermediateCerts []certificate.Certificate) bool {
	return x.TrustChainExist
}
