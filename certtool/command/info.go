package command

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"strings"

	"github.com/dawu415/PCFToolkit/certtool/certificateRepository/certificate"
	"github.com/dawu415/PCFToolkit/certtool/command/x509Lib"

	"github.com/dawu415/PCFToolkit/certtool/certificateRepository"
	"github.com/golang-collections/collections/stack"
)

// Info defines the struct holding the data necessary to execute an info command
type Info struct {
	certRepo      *certificateRepository.CertificateRepository
	x509VerifyLib x509Lib.Interface
}

// NewInfoCommand creates a new info command with a given certificate respository
func NewInfoCommand(certRepo *certificateRepository.CertificateRepository) *Info {
	return &Info{
		certRepo:      certRepo,
		x509VerifyLib: x509Lib.NewX509Lib(),
	}
}

// Name describes the name of this command
func (cmd *Info) Name() string {
	return "Info"
}

// Execute performs the command
func (cmd *Info) Execute() [][]Result {
	// Print info about all certs
	//  - Info about the cert
	//  - Trust chain graph
	var results [][]Result

	serverCertCount := len(cmd.certRepo.ServerCerts)
	if serverCertCount > 0 {
		results = make([][]Result, serverCertCount)
	}

	var certificates = [][]certificate.Certificate{
		cmd.certRepo.ServerCerts,
		cmd.certRepo.IntermediateCerts,
		cmd.certRepo.RootCACerts,
	}

	for _, certArray := range certificates {
		for idx, cert := range certArray {
			results[idx] = append(results[idx], cmd.stepRetrieveCertificateInfo(cert))

			if cert.Type == certificate.TypeServerCertificate {
				results[idx] = append(results[idx], cmd.stepBuildCertificateChain(cert))
			}
		}
	}

	return results
}

// stepRetrieveCertificateInfo retrieves key information representing the certificate
func (cmd *Info) stepRetrieveCertificateInfo(cert certificate.Certificate) Result {
	// Information returned  returned
	// - Issuer and Subject
	// - Whether it is a root, intermediate or server cert
	// - CN and SANs

	var crtTypeStr = map[int]string{
		certificate.TypeServerCertificate:       "Server Certificate",
		certificate.TypeRootCACertificate:       "Root Certificate",
		certificate.TypeIntermediateCertificate: "Intermediate Certificate",
	}

	verifyStepResult := StepResult{
		Message: fmt.Sprintf("Details of %s", cert.Label),
		Status:  StatusSuccess,

		StatusMessage: fmt.Sprintf("\n\tType: %s\n\n\tSubject: %s\n\n\tIssuer: %s\n\n\tCN: %s\n\n\tSANS: \n\t\t %s",
			crtTypeStr[cert.Type],
			cert.Certificate.Subject.String(),
			cert.Certificate.Issuer.String(),
			cert.Certificate.Subject.CommonName,
			strings.Join(cert.Certificate.DNSNames, ",\n\t\t ")),
	}

	return Result{
		Source:      SourceInfoCert,
		Title:       fmt.Sprintf("Retrieving Certificate Information"),
		StepResults: []StepResult{verifyStepResult},
		Error:       nil,
	}
}

// stepBuildCertificateChain builds the trust chain of the certificate to the root.
func (cmd *Info) stepBuildCertificateChain(cert certificate.Certificate) Result {

	var chainString = "\n\tLeaf: " + cert.Label + " \n\t\t -> "

	var searchCertStack = stack.New()

	searchCertStack.Push(cert)

	// Search the intermediate and determine the intermediate chain
	for true {
		var currentCert = searchCertStack.Pop().(certificate.Certificate)
		for _, intCert := range cmd.certRepo.IntermediateCerts {
			if intCert.Certificate.Subject.CommonName == currentCert.Certificate.Issuer.CommonName {
				chainString = chainString + intCert.Label + " \n\t\t\t-> "
				searchCertStack.Push(intCert)
				break
			}
		}
		if searchCertStack.Len() == 0 {
			searchCertStack.Push(currentCert)
			break
		}
	}

	// Search the root certs and determine the root chain
	if len(cmd.certRepo.RootCACerts) != 0 {
		for true {
			var currentCert = searchCertStack.Pop().(certificate.Certificate)
			for _, rootCert := range cmd.certRepo.RootCACerts {
				if rootCert.Certificate.Subject.CommonName == currentCert.Certificate.Issuer.CommonName {
					chainString = chainString + rootCert.Label
					searchCertStack.Push(rootCert)
					break
				}
			}
			if searchCertStack.Len() == 0 {
				searchCertStack.Push(currentCert)
				break
			}
		}
	}

	// If by now the searchStack still isn't empty, it means our provided root certs are not
	// part of this server cert's trust chain. We will search the system root certs instead.
	if searchCertStack.Len() != 0 {
		certPool, e := x509.SystemCertPool()
		if e == nil {
			for true {
				var currentCert = searchCertStack.Pop().(certificate.Certificate)
				for _, subject := range certPool.Subjects() {
					subjectRDN := &pkix.RDNSequence{}
					asn1.Unmarshal(subject, subjectRDN)
					var pkixName = pkix.Name{}
					pkixName.FillFromRDNSequence(subjectRDN)
					if pkixName.CommonName == currentCert.Certificate.Issuer.CommonName {
						chainString = chainString + "(System Store) " + pkixName.CommonName
						break
					}
				}
				if searchCertStack.Len() == 0 {
					break
				}
			}
		}
	}

	return Result{
		Source: SourceInfoCert,
		Title:  fmt.Sprintf("Building Certificate Chain"),
		StepResults: []StepResult{
			StepResult{
				Message:       fmt.Sprintf("%s", cert.Label),
				Status:        StatusSuccess,
				StatusMessage: chainString,
			},
		},
		Error: nil,
	}
}
