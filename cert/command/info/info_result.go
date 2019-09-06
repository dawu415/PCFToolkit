package info

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/dawu415/PCFToolkit/cert/certificateRepository/certificate"
	"github.com/xlab/treeprint"
)

// Result holds a set of results from the info command
type Result struct {
	certificates  []certificate.Certificate
	trustChains   map[certificate.Certificate]CertificateTrustChains
	hidePEMOutput bool
}

// CertificateInfo holds the publicly accessible Certificates and Computed TrustChains
type CertificateInfo struct {
	Certificates []certificate.Certificate
	TrustChains  map[certificate.Certificate]CertificateTrustChains
}

// CertificateTrustChains holds the set of trust chains for every server cert in certificateRepo
type CertificateTrustChains struct {
	Chains [][]certificate.Certificate
	Error  error
}

// dos2unixString converts a string containing \r\n to have only \n
func (result *Result) dos2unixString(input string) string {
	reg := regexp.MustCompile("\r{0,1}")
	return reg.ReplaceAllString(input, "${1}")
}

// Out outputs data to some specific stream. Currently, it is set to output to stdout
func (result *Result) Out() {

	var crtTypeStr = map[int]string{
		certificate.TypeServerCertificate:           "Server Certificate",
		certificate.TypeRootCACertificate:           "Root Certificate",
		certificate.TypeIntermediateCertificate:     "Intermediate Certificate",
		certificate.TypeSelfSignedServerCertificate: "Self-Signed Server Certificate",
	}

	for _, cert := range result.certificates {

		fmt.Print("\n")
		fmt.Println("---------------------------------------------------------------------")
		fmt.Printf("Details of %s\n", cert.Label)
		fmt.Println("---------------------------------------------------------------------")
		fmt.Printf("\n\tType: %s\n\n\tSubject: %s\n\n\tIssuer: %s\n\n\tCN: %s\n\n\tSANS: \n\t\t %s",
			crtTypeStr[cert.Type],
			cert.Certificate.Subject.String(),
			cert.Certificate.Issuer.String(),
			cert.Certificate.Subject.CommonName,
			strings.Join(cert.Certificate.DNSNames, ",\n\t\t "))
		fmt.Print("\n")

		// Top level result Root Certificates actually don't have a trust chain, so we'll have to print it here
		if cert.IsRootCert() && !result.hidePEMOutput {
			fmt.Printf("\n\tRoot CA Certificate - "+cert.Certificate.Subject.CommonName+":\n\n%s\n\n", result.dos2unixString(string(*cert.PemBlock)))
		}

		var sb = strings.Builder{}

		if trustChain, ok := result.trustChains[cert]; ok {
			var certTreeRoot = treeprint.New()
			if trustChain.Error == nil {
				for _, chain := range trustChain.Chains {
					var node = certTreeRoot
					for _, cert := range chain {

						var IssuerCommonName = cert.Certificate.Issuer.CommonName
						if len(cert.Certificate.Issuer.CommonName) <= 0 {
							IssuerCommonName = cert.Certificate.Issuer.String()
						}

						node = node.AddBranch(filepath.Base(cert.Label))
						node.AddNode("Subject: " + cert.Certificate.Subject.CommonName)
						node.AddNode("Issuer: " + IssuerCommonName)

						if !cert.IsRootCert() {
							node.AddNode("\b─┐")
						}
					}
					// If the last cert of this chain was not a root cert, we
					// should add a sign that it is incomplete
					if !chain[len(chain)-1].IsRootCert() {
						node = node.AddBranch("INCOMPLETE CHAIN")
					}
					fmt.Print("\nTrust Chain:\n")
					fmt.Println(certTreeRoot.String())

					if !result.hidePEMOutput {
						for _, cert = range chain {
							if cert.Type == certificate.TypeServerCertificate ||
								cert.Type == certificate.TypeSelfSignedServerCertificate {
								sb.WriteString("Server Certificate - " + cert.Certificate.Subject.CommonName + ":\n\n")
							} else if cert.Type == certificate.TypeIntermediateCertificate {
								sb.WriteString("Intermediate Certificate - " + cert.Certificate.Subject.CommonName + ":\n\n")
							} else {
								sb.WriteString("Root CA Certificate - " + cert.Certificate.Subject.CommonName + ":\n\n")
							}

							// This caters for the case if the certificate was actually a system root certificate
							// for which we are unable to extract
							if cert.PemBlock != nil {
								sb.WriteString(result.dos2unixString(string(*cert.PemBlock)))
								sb.WriteString("\n\n")
							} else {
								if cert.Type == certificate.TypeRootCACertificate {
									sb.WriteString("<System Root CAs are not extracted>\n\n")
								} else {
									sb.WriteString("Unable to extract certificate \n\n")
								}
							}
						}

						fmt.Print("\nChained Certificates:\n\n")
						fmt.Printf(sb.String())
					}
				}
			} else {
				fmt.Printf("Unable to print trust chain tree: %s", trustChain.Error.Error())
			}
		}

		fmt.Println("---------------------------------------------------------------------")
	}

}

// Data returns the raw data of Result
func (result *Result) Data() interface{} {
	return CertificateInfo{Certificates: result.certificates, TrustChains: result.trustChains}
}

// Status always returns true the for the Info command
func (result *Result) Status() bool {
	return true
}
