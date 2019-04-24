package x509Lib

import (
	"crypto/x509"

	"github.com/dawu415/PCFToolkit/certtool/certificateRepository/certificate"
)

// Interface defines a thin wrapper to the crypto/x509 module
type Interface interface {
	TrustChainExistOn(serverCert certificate.Certificate, rootCerts, intermediateCerts []certificate.Certificate) bool
}

// X509Lib defines the data associated with the x509Kib
type X509Lib struct {
}

// NewX509Lib generates a new X509Lib struct
func NewX509Lib() *X509Lib {
	return &X509Lib{}
}

// TrustChainExistOn determines if a trust chain exists for a given serverCert and its associated intermediate and rootCerts.
func (x *X509Lib) TrustChainExistOn(serverCert certificate.Certificate, rootCerts, intermediateCerts []certificate.Certificate) bool {

	trustChainExists := false
	verifyOptions := x.createCertVerifyOptionsWith(rootCerts, intermediateCerts)

	if _, certVerifyStatus := serverCert.Certificate.Verify(verifyOptions); certVerifyStatus != nil {
		trustChainExists = false
	} else {
		trustChainExists = true
	}

	return trustChainExists
}

// convertCertRepoCertArrayToX509CertPool is a helper function that pushes an array of
// Certificates into an crypto/x509 CertPool
func (x *X509Lib) convertCertRepoCertArrayToX509CertPool(certArray []certificate.Certificate) *x509.CertPool {
	certPool := x509.NewCertPool()
	// Move the certs into a cert pool
	for _, cert := range certArray {
		certPool.AddCert(cert.Certificate)
	}
	return certPool
}

// createCertVerifyOptionsWith will create a x509.VerifyOptions struct, which is used to specify
// which input root CA certs and the available intermediate certs to use for verification.
// If rootCerts is nil, the root CA certs on the system is used instead (e.g., in /etc/ssl)
func (x *X509Lib) createCertVerifyOptionsWith(rootCerts, intermediateCerts []certificate.Certificate) x509.VerifyOptions {

	var rootCertPool *x509.CertPool
	if rootCerts != nil {
		rootCertPool = x.convertCertRepoCertArrayToX509CertPool(rootCerts)
	}
	intermediateCertPool := x.convertCertRepoCertArrayToX509CertPool(intermediateCerts)

	return x509.VerifyOptions{
		Roots:         rootCertPool,
		Intermediates: intermediateCertPool,
	}
}
