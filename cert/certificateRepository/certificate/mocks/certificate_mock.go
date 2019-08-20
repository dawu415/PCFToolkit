package certificate_mock

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"time"

	"github.com/dawu415/PCFToolkit/cert/certificateRepository/certificate"
)

// CertificateMock describes a mock for Certificate
type CertificateMock struct {
	CertificateType          int
	LoadPEMCertificateFailed bool
	DNSNames                 []string
	NotBefore                time.Time
	NotAfter                 time.Time
	PublicKey                interface{}
	IssuerCN                 string
	SubjectCN                string
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
			Type:     cert.CertificateType,
			Label:    label,
			PemBlock: &[]byte{},
			Certificate: &x509.Certificate{
				Raw:       PEMCertBytes,
				DNSNames:  cert.DNSNames,
				NotAfter:  cert.NotAfter,
				NotBefore: cert.NotBefore,
				PublicKey: cert.PublicKey,
				Issuer:    pkix.Name{CommonName: cert.IssuerCN},
				Subject:   pkix.Name{CommonName: cert.SubjectCN},
			}, // Placeholder to hold the PEMCertBytes
		},
	}, err
}
