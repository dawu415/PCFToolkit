package x509parser

import (
	"crypto/x509"
)

// X509ParserInterface defines the methods that can be called to parse a certificate or private key
type X509ParserInterface interface {
	ParseCertificates(asn1Data []byte) ([]*x509.Certificate, error)
	ParsePrivateKey(der []byte) (key interface{}, err error)
}

// X509ParseData holds the for the x509Parser
type X509ParseData struct {
}

// Newx509Parser instantiates an object for the x509Parser interface
func Newx509Parser() X509ParserInterface {
	return &X509ParseData{}
}

// ParseCertificates parses an x509 certificate with byte input as asn.1
func (x *X509ParseData) ParseCertificates(asn1Data []byte) ([]*x509.Certificate, error) {
	return x509.ParseCertificates(asn1Data)
}

// ParsePrivateKey parses a private key in DER byte format. It is assumed that the private key
// is unencrypted at this point.
func (x *X509ParseData) ParsePrivateKey(der []byte) (key interface{}, err error) {
	return x509.ParsePKCS8PrivateKey(der)
}
