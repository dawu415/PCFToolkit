package certificate

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"reflect"
	"strings"

	"github.com/asaskevich/govalidator"
	"github.com/dawu415/PCFToolkit/cert/certificateRepository/pemDecoder"
	x509parser "github.com/dawu415/PCFToolkit/cert/certificateRepository/x509Parser"
)

// Constants/Enums used to define a certificate type
const (
	TypeServerCertificate           = iota
	TypeRootCACertificate           = iota
	TypeIntermediateCertificate     = iota
	TypeSelfSignedServerCertificate = iota
)

// PEMCertificateLoaderInterface defines the interface to load a PEM certificate
type PEMCertificateLoaderInterface interface {
	LoadPEMCertificates(label string, PEMCertBytes []byte) ([]Certificate, error)
}

// Certificate defines a generic certificate that is specified by its Type, the certificate and a label to identify it
type Certificate struct {
	Type        int
	Label       string
	Certificate *x509.Certificate
	PemBlock    *[]byte
	pemDecoder  pemDecoder.PEMDecoderInterface
	x509Parser  x509parser.X509ParserInterface
}

// NewCustomPEMCertificate creates an interface with custom decoder and x509 Parser that enables the parsing and loading of PEM certificates
func NewCustomPEMCertificate(decoder pemDecoder.PEMDecoderInterface, parser x509parser.X509ParserInterface) PEMCertificateLoaderInterface {
	return &Certificate{
		pemDecoder: decoder,
		x509Parser: parser,
	}
}

// NewPEMCertificate creates an interface that enables the parsing and loading of PEM certificates
func NewPEMCertificate() PEMCertificateLoaderInterface {
	return &Certificate{
		pemDecoder: pemDecoder.NewPEMDecoder(),
		x509Parser: x509parser.Newx509Parser(),
	}
}

// LoadPEMCertificates reads in PEM certificate bytes. This may contain multiple certificates.
// This method will decode each certificate in PEMCertBytes and return them as an array of Certificate
func (cert *Certificate) LoadPEMCertificates(label string, PEMCertBytes []byte) ([]Certificate, error) {
	var certificates []Certificate
	var err error
	var certCount = 0
	var startByteIdx = 0
	var junkByteCount = 0
	remainder := PEMCertBytes
	for len(remainder) > 0 {
		var singlePEMCert *pem.Block
		singlePEMCert, remainder = cert.pemDecoder.Decode(remainder)

		// If for some reason we weren't abe to decode this block of data, let's just
		// remove a character until we reach something that is decodable or
		// exhaust all characters in remainder and allow this loop to break.
		// This handles the situation where there is an extra newline or carriage return
		// or, when there shouldn't, there is extra data in the file in between certificates
		// for some reason.
		// We should also increment the position of the pointer in PEMCertBytes at where
		// we are located in the array
		if singlePEMCert == nil {
			remainder = remainder[1:]
			junkByteCount++
			continue
		}

		decodedSinglePEMCertLen := len(PEMCertBytes) - junkByteCount - len(remainder)
		originalCertBytes := PEMCertBytes[startByteIdx+junkByteCount : decodedSinglePEMCertLen]
		startByteIdx = decodedSinglePEMCertLen
		certCount++

		if err == nil {
			var x509Certs []*x509.Certificate
			x509Certs, err = cert.x509Parser.ParseCertificates(singlePEMCert.Bytes)
			if err == nil {
				for _, x509Cert := range x509Certs {
					certificates = append(certificates,
						Certificate{
							Type:        cert.determineCertificateType(x509Cert),
							Label:       label,
							Certificate: x509Cert,
							PemBlock:    &originalCertBytes,
						})
				}
			}

		}
	}

	if err == nil && certCount == 0 {
		err = fmt.Errorf("No valid PEM certificates were decoded")
	}

	return certificates, err
}

// IsRootCert returns true if the input certificate is a root certificate
func (cert *Certificate) IsRootCert() bool {
	return cert.isRootCert(cert.Certificate)
}

func (cert *Certificate) determineCertificateType(certificate *x509.Certificate) int {
	if cert.isServerCert(certificate) {
		if cert.isRootCert(certificate) {
			return TypeSelfSignedServerCertificate
		} else {
			return TypeServerCertificate
		}
	} else if cert.isRootCert(certificate) {
		return TypeRootCACertificate
	}
	return TypeIntermediateCertificate
}

func (cert *Certificate) isServerCert(input *x509.Certificate) bool {
	return govalidator.IsURL(strings.Replace(input.Subject.CommonName, "*.", "", -1)) ||
		govalidator.IsIP(input.Subject.CommonName) || cert.hasURLorIPSANS(input)
}

func (cert *Certificate) hasURLorIPSANS(input *x509.Certificate) bool {
	var hasURLorIPSANS = false
	if len(input.DNSNames) > 0 {
		for _, dnsName := range input.DNSNames {
			hasURLorIPSANS = govalidator.IsURL(strings.Replace(dnsName, "*.", "", -1)) || govalidator.IsIP(dnsName)
			if hasURLorIPSANS == true {
				break
			}
		}
	}
	return hasURLorIPSANS
}

func (cert *Certificate) isRootCert(input *x509.Certificate) bool {
	// A self signed cert is one
	// where the Issuer and Subject are identical.
	// A root cert has this property, plus potentially
	// some other tests such as 'Basic Contraints IsCritical =True and IsCA = True" and a number of
	// extensions (id-ce) that could be used to determine this fact.
	// For simplicity, we'll use the test that checks that the issuer and subject are identical
	// See http://www.ietf.org/rfc/rfc5280.txt for more information regarding root certificate identification
	return reflect.DeepEqual(input.Issuer, input.Subject)
}
