package certificate_mock

import (
	"crypto/x509"
	"fmt"

	"github.com/dawu415/PCFToolkit/certtool/certificateRepository/certificate"
)

// CertificateMock describes a mock for Certificate
type CertificateMock struct {
	CertificateType          int
	LoadPEMCertificateFailed bool
}

// NewPEMCertificateMock creates a mock interface for the PEMCertificate for testing
func NewPEMCertificateMock() *CertificateMock {
	return &CertificateMock{}
}

// LoadPEMCertificates reads in PEM certificate bytes. This may contain multiple certificates.
// This method will decode each certificate in PEMCertBytes and return them as an array of Certificate
func (cert *CertificateMock) LoadPEMCertificates(label string, PEMCertBytes []byte) ([]certificate.Certificate, error) {
	var err error
	if cert.LoadPEMCertificateFailed {
		err = fmt.Errorf("LoadPEMCertificateFailed set to TRUE")
	}

	return []certificate.Certificate{
		certificate.Certificate{
			Type:        cert.CertificateType,
			Label:       label,
			Certificate: &x509.Certificate{Raw: PEMCertBytes}, // Placeholder to hold the PEMCertBytes
		},
	}, err
}
