package info

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/dawu415/PCFToolkit/certtool/certificateRepository/certificate"
	"github.com/xlab/treeprint"
)

// Result holds a set of results from the info command
type Result struct {
	certificates []certificate.Certificate
	trustChains  map[certificate.Certificate]CertificateTrustChains
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

		if trustChain, ok := result.trustChains[cert]; ok {
			var certTreeRoot = treeprint.New()
			if trustChain.Error == nil {
				for _, chain := range trustChain.Chains {
					var node = certTreeRoot
					for _, cert := range chain {
						node = node.AddBranch(filepath.Base(cert.Label))
						node.AddNode("Subject: " + cert.Certificate.Subject.CommonName)
						node.AddNode("Issuer: " + cert.Certificate.Issuer.CommonName)

						if !cert.IsRootCert() {
							node.AddNode("\b─┐")
						}
					}
					// If the last cert of this chain was not a root cert, we
					// should add a sign that it is incomplete
					if !chain[len(chain)-1].IsRootCert() {
						node = node.AddBranch("INCOMPLETE CHAIN")
					}
				}
				fmt.Print("\nTrust Chain:\n")
				fmt.Println(certTreeRoot.String())
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
