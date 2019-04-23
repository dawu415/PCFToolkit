package x509parser_mock

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"

	"github.com/dawu415/PCFToolkit/certtool/certificateRepository/certificate"
)

// X509ParseDataMock holds the data for the x509ParserMock
type X509ParseDataMock struct {
	ParseCertificatesFailed bool
	ParsePrivateKeyFailed   bool
	CertificateType         int
}

// Newx509ParserMock instantiates an object for the x509ParserMock interface
func Newx509ParserMock() *X509ParseDataMock {
	return &X509ParseDataMock{}
}

// ParseCertificates parses an x509 certificate with byte input as asn.1
func (x *X509ParseDataMock) ParseCertificates(asn1Data []byte) ([]*x509.Certificate, error) {
	var err error
	if x.ParseCertificatesFailed {
		err = fmt.Errorf("ParseCertificatesFailed was set to TRUE")
	}

	fakeCert := x509.Certificate{
		Raw: asn1Data,
	}

	pkixIssuerA := pkix.Name{
		OrganizationalUnit: []string{"dawu authority Corp"},
	}
	pkixIssuerB := pkix.Name{
		OrganizationalUnit: []string{"dawu authority Sub-Corp"},
	}
	pkixSubject := pkix.Name{
		CommonName: "*.dawu.io",
	}

	if x.CertificateType == certificate.TypeServerCertificate {
		fakeCert.Subject = pkixSubject
		fakeCert.Issuer = pkixIssuerA
	} else if x.CertificateType == certificate.TypeRootCACertificate {
		fakeCert.Subject = pkixIssuerA
		fakeCert.Issuer = pkixIssuerA
		fakeCert.IsCA = true
		fakeCert.BasicConstraintsValid = true
	} else {
		fakeCert.Issuer = pkixIssuerA
		fakeCert.Subject = pkixIssuerB
	}

	return []*x509.Certificate{
		&fakeCert,
	}, err
}

// ParsePrivateKey parses a private key in DER byte format. It is assumed that the private key
// is unencrypted at this point.
func (x *X509ParseDataMock) ParsePrivateKey(der []byte) (interface{}, error) {
	var err error
	if x.ParsePrivateKeyFailed {
		err = fmt.Errorf("ParsePrivateKeyFailed was set to TRUE")
	}

	return der, err
}
