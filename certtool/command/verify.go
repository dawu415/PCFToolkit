package command

import (
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/dawu415/PCFSToolkit/command/x509Lib"
	"github.com/oleiade/reflections"

	"github.com/dawu415/PCFSToolkit/certificateRepository/certificate"
	"github.com/dawu415/PCFSToolkit/certificateRepository/privatekey"

	"github.com/dawu415/PCFSToolkit/certificateRepository"
)

// Verify defines the struct holding the data necessary to execute a command
type Verify struct {
	certRepo      *certificateRepository.CertificateRepository
	systemDomain  string
	appsDomain    string
	x509VerifyLib *x509Lib.X509Lib
}

func NewVerifyCommand(certRepo *certificateRepository.CertificateRepository, systemDoman, appDomain string) *Verify {
	return &Verify{
		certRepo:      certRepo,
		systemDomain:  systemDoman,
		appsDomain:    appDomain,
		x509VerifyLib: x509Lib.NewX509Lib(),
	}
}

func (cmd *Verify) Name() string {
	return "Verify"
}

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

func (cmd *Verify) stepCheckCertificateWithProvidedPrivateKey(serverCert certificate.Certificate, privateKeys map[string]privatekey.PrivateKey) Result {
	// If the modulus of the private key is equal the server cert's modulus, then it matches
	var err error
	stepResult := StepResult{
		Source: cmd.Name() + "- Verify Certificate And Private Key",
	}

	if key, ok := privateKeys[serverCert.Label]; ok {
		stepResult.Message = fmt.Sprintf("Verifying matching certificate and key:\t%s with %s\n", serverCert.Label, key.Label)
		var serverCertModulus interface{}
		var privateKeyModulus interface{}

		if serverCertModulus, err = reflections.GetField(serverCert.Certificate.PublicKey, "N"); err == nil {
			if privateKeyModulus, err = reflections.GetField(key.PrivateKey, "N"); err == nil {
				if reflect.DeepEqual(serverCertModulus, privateKeyModulus) {
					stepResult.Status = StatusSuccess
					stepResult.StatusMessage = "OK!"
				} else {
					stepResult.Status = StatusFailed
					stepResult.StatusMessage = "FAILED!"
				}
			}
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
