package command

import (
	"crypto/rsa"
	"fmt"
	"strings"
	"time"

	"github.com/dawu415/PCFToolkit/certtool/command/x509Lib"

	"github.com/dawu415/PCFToolkit/certtool/certificateRepository/certificate"
	"github.com/dawu415/PCFToolkit/certtool/certificateRepository/privatekey"

	"github.com/dawu415/PCFToolkit/certtool/certificateRepository"
)

// Verify defines the struct holding the data necessary to execute a command
type Verify struct {
	certRepo      *certificateRepository.CertificateRepository
	systemDomain  string
	appsDomain    string
	x509VerifyLib *x509Lib.X509Lib
}

// NewVerifyCommand creates a new verify command with a given certificate respository, system domain and app domain
func NewVerifyCommand(certRepo *certificateRepository.CertificateRepository, systemDoman, appDomain string) *Verify {
	return &Verify{
		certRepo:      certRepo,
		systemDomain:  systemDoman,
		appsDomain:    appDomain,
		x509VerifyLib: x509Lib.NewX509Lib(),
	}
}

// Name describes the name of this command
func (cmd *Verify) Name() string {
	return "Verify"
}

// Execute performs the command
func (cmd *Verify) Execute() []Result {

	var results []Result
	useSystemRootCerts := true
	for _, serverCert := range cmd.certRepo.ServerCerts {
		// Check if the user provided the root CA certs.
		if len(cmd.certRepo.RootCACerts) == 0 {
			// If not, we should use the system CA cert store.
			results = append(results, cmd.stepCheckCertificateTrustChain(serverCert, useSystemRootCerts))
		} else {
			// Otherwise, test both the provided root CA certs and the system store.
			results = append(results, cmd.stepCheckCertificateTrustChain(serverCert, !useSystemRootCerts))
			results = append(results, cmd.stepCheckCertificateTrustChain(serverCert, useSystemRootCerts))
		}

		results = append(results, cmd.stepCheckCertificateDomainsForPCF(serverCert))
		results = append(results, cmd.stepCheckCertificateExpiry(serverCert))
		results = append(results, cmd.stepCheckCertificateWithProvidedPrivateKey(serverCert, cmd.certRepo.PrivateKeys))
	}
	return results
}

// stepCheckCertificateTrustChain determines if a server certificate has a trust chain with
// provided intermediate and root certificates.
// If ignoreCertRepoRootCA is true, the command ensures that the Certificate trust chain is determined from
// the system trust store instead of provided root certificates.
func (cmd *Verify) stepCheckCertificateTrustChain(serverCert certificate.Certificate, ignoreCertRepoRootCA bool) Result {

	rootCertMessage := "using System Root Certificates."
	var rootCertificates []certificate.Certificate
	if !ignoreCertRepoRootCA {
		rootCertificates = cmd.certRepo.RootCACerts
		rootCertMessage = "using provided Root Certificates."
	}

	hasTrustedChain := cmd.x509VerifyLib.TrustChainExistOn(serverCert, rootCertificates, cmd.certRepo.IntermediateCerts)

	verifyStepResult := StepResult{
		Source:  cmd.Name() + "- Verify Certificate Trust",
		Message: fmt.Sprintf("Verifying trust chain of %s", serverCert.Label),
	}

	if hasTrustedChain {
		verifyStepResult.Status = StatusSuccess
		verifyStepResult.StatusMessage = "OK!"
	} else {
		verifyStepResult.Status = StatusFailed
		verifyStepResult.StatusMessage = "FAILED!"
	}

	return Result{
		Title:       fmt.Sprintf("Verifying Certificate Trust Chain %s", rootCertMessage),
		StepResults: []StepResult{verifyStepResult},
		Error:       nil,
	}
}

// stepCheckCertificateDomainsForPCF checks to see if the required PCF DNS names exists in a
// server certificate
func (cmd *Verify) stepCheckCertificateDomainsForPCF(serverCert certificate.Certificate) Result {

	DNSNames := []string{
		"*." + cmd.appsDomain,
		"*." + cmd.systemDomain,
		"*.uaa." + cmd.systemDomain,
		"*.login." + cmd.systemDomain,
	}

	var resultsArray []StepResult
	for _, dnsName := range DNSNames {
		var found = false
		for _, dnsInCert := range serverCert.Certificate.DNSNames {
			if strings.Contains(dnsInCert, dnsName) {
				found = true
				break
			}
		}

		stepResult := StepResult{
			Source:  cmd.Name() + "- Verify Certificate SANs",
			Message: fmt.Sprintf("Checking %s", dnsName),
		}

		if found {
			stepResult.Status = StatusSuccess
			stepResult.StatusMessage = "FOUND!"
		} else {
			stepResult.Status = StatusFailed
			stepResult.StatusMessage = "X"
		}
		resultsArray = append(resultsArray, stepResult)

	}
	return Result{
		Title:       "Checking PCF SANs on Certificate",
		StepResults: resultsArray,
		Error:       nil,
	}
}

// stepCheckCertificateExpiry checks the expiry of a certificate with in a 6 month period.
func (cmd *Verify) stepCheckCertificateExpiry(serverCert certificate.Certificate) Result {

	stepResult := StepResult{
		Source:  cmd.Name() + "- Verify Certificate Expiry",
		Message: fmt.Sprintf("Verifying %s\nValid From:\t%s UNTIL %s\n", serverCert.Label, serverCert.Certificate.NotBefore.String(), serverCert.Certificate.NotAfter.String()),
	}

	currentTime := time.Now()

	if currentTime.After(serverCert.Certificate.NotBefore) &&
		currentTime.Before(serverCert.Certificate.NotAfter) {
		// Check if our server cert will expire within the next 6 months.
		if currentTime.AddDate(0, 6, 0).Before(serverCert.Certificate.NotAfter) {
			stepResult.Status = StatusSuccess
			stepResult.StatusMessage = "OK!"
		} else {
			stepResult.Status = StatusWarning
			stepResult.StatusMessage = fmt.Sprintf("WARNING - This certificate expires in %0.2f days (%0.2f months)\n", serverCert.Certificate.NotAfter.Sub(currentTime).Hours()/24, serverCert.Certificate.NotAfter.Sub(currentTime).Hours()/(24*365/12))
		}
	} else {
		stepResult.Status = StatusSuccess
		stepResult.StatusMessage = "FAILED! Certificate Expired!"
	}

	return Result{
		Title:       "Checking Certificate Expiry",
		StepResults: []StepResult{stepResult},
		Error:       nil,
	}
}

// stepCheckCertificateWithProvidedPrivateKey determines if a server certificate and its corresponding
// provided private key match.
func (cmd *Verify) stepCheckCertificateWithProvidedPrivateKey(serverCert certificate.Certificate, privateKeys map[string]privatekey.PrivateKey) Result {
	// If the modulus of the private key is equal the server cert's modulus, it matches
	var err error
	stepResult := StepResult{
		Source: cmd.Name() + "- Verify Certificate And Private Key",
	}

	if key, ok := privateKeys[serverCert.Label]; ok {
		stepResult.Message = fmt.Sprintf("Verifying matching certificate and key:\t%s with %s\n", serverCert.Label, key.Label)

		if pubKey, ok := serverCert.Certificate.PublicKey.(rsa.PublicKey); ok {
			if privateKey, ok := key.PrivateKey.(rsa.PrivateKey); ok {
				if pubKey.N == privateKey.N {
					stepResult.Status = StatusSuccess
					stepResult.StatusMessage = "OK!"
				} else {
					stepResult.Status = StatusFailed
					stepResult.StatusMessage = "FAILED!"
				}
			} else {
				err = fmt.Errorf("Something is wrong with the private Key. Unable to assert the private key into an RSA PrivateKey Type")
			}
		} else {
			err = fmt.Errorf("Something is wrong with the public Key. Unable to assert the public key into an RSA PublicKey Type")

		}

	} else {
		stepResult.Message = "Could not check matching of certificate and private key. Private key not provided."
		stepResult.Status = StatusNotChecked
		stepResult.StatusMessage = "NOT CHECKED"
	}

	return Result{
		Title:       "Checking the certificate and private key match",
		StepResults: []StepResult{stepResult},
		Error:       err,
	}
}
