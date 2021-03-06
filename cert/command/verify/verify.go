package verify

import (
	"crypto/rsa"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/dawu415/PCFToolkit/cert/command/result"

	"github.com/dawu415/PCFToolkit/cert/command/x509Lib"

	"github.com/dawu415/PCFToolkit/cert/certificateRepository/certificate"
	"github.com/dawu415/PCFToolkit/cert/certificateRepository/privatekey"

	"github.com/dawu415/PCFToolkit/cert/certificateRepository"
)

// Verify defines the struct holding the data necessary to execute a command
type Verify struct {
	certRepo      *certificateRepository.CertificateRepository
	options       *Options
	x509VerifyLib x509Lib.Interface
}

// NewVerifyCommand creates a new verify command with a given certificate respository, system domain and app domain
func NewVerifyCommand(certRepo *certificateRepository.CertificateRepository, verifyOptions *Options) *Verify {
	return NewVerifyCommandCustomVerifyLib(certRepo, verifyOptions, x509Lib.NewX509Lib())
}

// NewVerifyCommandCustomVerifyLib returns a verify command with given certificate repository, system domain, app domain and an x509VerifyLib
func NewVerifyCommandCustomVerifyLib(certRepo *certificateRepository.CertificateRepository, verifyOptions *Options, verifyLib x509Lib.Interface) *Verify {
	// If all verification steps are false (it wasn't specified by user) then show all the verify steps
	if verifyOptions.VerifyTrustChain == false &&
		verifyOptions.VerifyDNS == false &&
		verifyOptions.VerifyCertPrivateKeyMatch == false &&
		verifyOptions.VerifyCertExpiration == false {
		verifyOptions.VerifyTrustChain = true
		verifyOptions.VerifyDNS = true
		verifyOptions.VerifyCertPrivateKeyMatch = true
		verifyOptions.VerifyCertExpiration = true
	}

	return &Verify{
		certRepo:      certRepo,
		options:       verifyOptions,
		x509VerifyLib: verifyLib,
	}
}

// Name describes the name of this command
func (cmd *Verify) Name() string {
	return "Verify"
}

// Execute performs the command
func (cmd *Verify) Execute() result.Result {

	var results [][]ResultData
	useSystemRootCerts := true

	allCerts := append(append(cmd.certRepo.ServerCerts, cmd.certRepo.IntermediateCerts...), cmd.certRepo.RootCACerts...)
	certCount := len(allCerts)
	if certCount > 0 {
		results = make([][]ResultData, certCount)
	}
	for idx, cert := range allCerts {

		// If a contains filter exists, Oly process certs whose subject or individual SANs contains the text in specified in ContainsFilter string.
		if len(cmd.options.ContainsFilter) > 0 {
			if !strings.Contains(strings.ToLower(cert.Certificate.Subject.String()), strings.ToLower(cmd.options.ContainsFilter)) &&
				!strings.Contains(strings.ToLower(strings.Join(cert.Certificate.DNSNames, " ")), strings.ToLower(cmd.options.ContainsFilter)) {
				continue
			}
		}

		// Only do trust chain verification on Server Certificates
		if cmd.options.VerifyTrustChain && (cert.Type == certificate.TypeServerCertificate || cert.Type == certificate.TypeSelfSignedServerCertificate) {
			// Check if the user provided the root CA certs.
			if len(cmd.certRepo.RootCACerts) == 0 {
				cmdResult := cmd.stepCheckCertificateTrustChain(cert, useSystemRootCerts)
				// If not, we should use the system CA cert store.
				results[idx] = append(results[idx], cmdResult)
			} else {
				// Otherwise, test both the provided root CA certs and the system store.
				resultUsingProvidedRootCA := cmd.stepCheckCertificateTrustChain(cert, !useSystemRootCerts)
				resultUsingSystemRootCA := cmd.stepCheckCertificateTrustChain(cert, useSystemRootCerts)

				// We should update the overall success here to be true, if any of them succeeded because it means it found
				// a trust chain.
				if resultUsingProvidedRootCA.OverallSucceeded == true ||
					resultUsingSystemRootCA.OverallSucceeded == true {
					resultUsingProvidedRootCA.OverallSucceeded = true
					resultUsingSystemRootCA.OverallSucceeded = true
				}

				results[idx] = append(results[idx], resultUsingProvidedRootCA)
				results[idx] = append(results[idx], resultUsingSystemRootCA)

			}
		}
		// Verify that the SANS match the particular PCF required domains.
		if cmd.options.VerifyDNS && (cert.Type == certificate.TypeServerCertificate || cert.Type == certificate.TypeSelfSignedServerCertificate) {
			results[idx] = append(results[idx], cmd.stepCheckCertificateDomainsForPCF(cert))
		}

		// We can verify expiration on all certificate types
		if cmd.options.VerifyCertExpiration {
			results[idx] = append(results[idx], cmd.stepCheckCertificateExpiry(cert))
		}

		// If a private key is associated with a server certificate, check to ensure that the private key correspond to the certificate
		if cmd.options.VerifyCertPrivateKeyMatch && (cert.Type == certificate.TypeServerCertificate || cert.Type == certificate.TypeSelfSignedServerCertificate) {
			results[idx] = append(results[idx], cmd.stepCheckCertificateWithProvidedPrivateKey(cert, cmd.certRepo.PrivateKeys))
		}
	}
	return &Result{
		results: results,
	}
}

// generateSignatureString generates a short output of the pem block. This will aid certificate identification
// should a filename not exist.
func (cmd *Verify) generateSignatureString(pemBlock string) string {
	//Remove the top and bottom comment lines
	reg := regexp.MustCompile("-----.*-----\r{0,1}\n{0,1}")
	startBlock := reg.ReplaceAllString(pemBlock, "${1}")
	// Remove new lines
	reg = regexp.MustCompile("\r{0,1}\n{0,1}")
	startBlock = reg.ReplaceAllString(startBlock, "${1}")

	returnString := startBlock

	if len(startBlock) != 0 && len(startBlock) >= 10 {
		returnString = startBlock[:10] + "..." + startBlock[len(startBlock)-10:]
	}

	return returnString
}

// stepCheckCertificateTrustChain determines if a server certificate has a trust chain with
// provided intermediate and root certificates.
// If ignoreCertRepoRootCA is true, the command ensures that the Certificate trust chain is determined from
// the system trust store instead of provided root certificates.
func (cmd *Verify) stepCheckCertificateTrustChain(inputCert certificate.Certificate, ignoreCertRepoRootCA bool) ResultData {

	rootCertMessage := "using System Root Certificates."
	var rootCertificates []certificate.Certificate
	if !ignoreCertRepoRootCA {
		rootCertificates = cmd.certRepo.RootCACerts
		rootCertMessage = "using provided Root Certificates."
	}

	hasTrustedChain := cmd.x509VerifyLib.TrustChainExistOn(inputCert, rootCertificates, cmd.certRepo.IntermediateCerts)

	verifyStepResult := StepResultData{
		Message: fmt.Sprintf("Verifying trust chain of %s", inputCert.Label),
	}

	if hasTrustedChain {
		verifyStepResult.Status = result.StatusSuccess
		verifyStepResult.StatusMessage = "OK!"
	} else {
		verifyStepResult.Status = result.StatusFailed
		verifyStepResult.StatusMessage = "FAILED!"
	}

	return ResultData{
		Source:           SourceVerifyTrustChain,
		Title:            fmt.Sprintf("Verifying Certificate Trust Chain %s - %s", rootCertMessage, inputCert.Certificate.Subject.String()),
		StepResults:      []StepResultData{verifyStepResult},
		OverallSucceeded: verifyStepResult.Status == result.StatusSuccess,
		Signature:        cmd.generateSignatureString(string(*inputCert.PemBlock)),
		Error:            nil,
	}
}

// stepCheckCertificateDomainsForPCF checks to see if the required PCF DNS names exists in a
// server certificate
func (cmd *Verify) stepCheckCertificateDomainsForPCF(inputCert certificate.Certificate) ResultData {

	// We'll add the period at the end of the DNS names to ensure
	// our string comparison method is strict on the format
	DNSNames := []string{
		"*." + cmd.options.AppsDomain + ".",
		"*." + cmd.options.SystemDomain + ".",
		"*.uaa." + cmd.options.SystemDomain + ".",
		"*.login." + cmd.options.SystemDomain + ".",
	}

	var overralResult = true
	var resultsArray []StepResultData
	for _, dnsName := range DNSNames {
		var found = false
		for _, dnsInCert := range inputCert.Certificate.DNSNames {
			if strings.Contains(dnsInCert, dnsName) {
				found = true
				break
			}
		}

		stepResult := StepResultData{
			Message: fmt.Sprintf("Checking %s", dnsName),
		}

		if found {
			stepResult.Status = result.StatusSuccess
			stepResult.StatusMessage = "FOUND!"
		} else {
			overralResult = false
			stepResult.Status = result.StatusFailed
			stepResult.StatusMessage = "X"
		}
		resultsArray = append(resultsArray, stepResult)

	}
	return ResultData{
		Source:           SourceVerifyCertSANS,
		Title:            fmt.Sprintf("Checking PCF SANs on Certificate - %s", inputCert.Certificate.Subject.String()),
		StepResults:      resultsArray,
		OverallSucceeded: overralResult,
		Signature:        cmd.generateSignatureString(string(*inputCert.PemBlock)),
		Error:            nil,
	}
}

// stepCheckCertificateExpiry checks the expiry of a certificate with in a 6 month period.
func (cmd *Verify) stepCheckCertificateExpiry(inputCert certificate.Certificate) ResultData {

	stepResult := StepResultData{
		Message: fmt.Sprintf("Verifying %s\nValid From:\t%s UNTIL %s\n", inputCert.Label, inputCert.Certificate.NotBefore.String(), inputCert.Certificate.NotAfter.String()),
	}

	currentTime := time.Now()

	if currentTime.After(inputCert.Certificate.NotBefore) &&
		currentTime.Before(inputCert.Certificate.NotAfter) {
		// Check if our server cert will expire within the next CertExpiryWarningMonths months.
		if currentTime.AddDate(0, cmd.options.MinimumMonthsWarningToExpire, 0).Before(inputCert.Certificate.NotAfter) {
			stepResult.Status = result.StatusSuccess
			stepResult.StatusMessage = fmt.Sprintf("OK! - This certificate expires in %0.2f days (%0.2f months)\n", inputCert.Certificate.NotAfter.Sub(currentTime).Hours()/24, inputCert.Certificate.NotAfter.Sub(currentTime).Hours()/(24*365/12))
		} else {
			stepResult.Status = result.StatusWarning
			stepResult.StatusMessage = fmt.Sprintf("WARNING - Within the next %d months, this certificate expires in %0.2f days (%0.2f months)\n", cmd.options.MinimumMonthsWarningToExpire, inputCert.Certificate.NotAfter.Sub(currentTime).Hours()/24, inputCert.Certificate.NotAfter.Sub(currentTime).Hours()/(24*365/12))
		}
	} else {
		stepResult.Status = result.StatusFailed
		stepResult.StatusMessage = "FAILED! Certificate Expired!"
	}

	return ResultData{
		Source:           SourceVerifyCertExpiry,
		Title:            fmt.Sprintf("Checking Certificate Expiry - %s", inputCert.Certificate.Subject.String()),
		StepResults:      []StepResultData{stepResult},
		OverallSucceeded: stepResult.Status == result.StatusSuccess,
		Signature:        cmd.generateSignatureString(string(*inputCert.PemBlock)),
		Error:            nil,
	}
}

// stepCheckCertificateWithProvidedPrivateKey determines if a server certificate and its corresponding
// provided private key match.
func (cmd *Verify) stepCheckCertificateWithProvidedPrivateKey(inputCert certificate.Certificate, privateKeys map[string]privatekey.PrivateKey) ResultData {
	// If the modulus of the private key is equal the server cert's modulus, it matches
	var err error
	stepResult := StepResultData{}

	if key, ok := privateKeys[inputCert.Label]; ok {
		stepResult.Message = fmt.Sprintf("Verifying matching certificate and key:\t%s with %s\n", inputCert.Label, key.Label)

		if pubKey, ok := inputCert.Certificate.PublicKey.(rsa.PublicKey); ok {
			if privateKey, ok := key.PrivateKey.(rsa.PrivateKey); ok {

				if pubKey.N.Cmp(privateKey.N) == 0 {
					stepResult.Status = result.StatusSuccess
					stepResult.StatusMessage = "OK!"
				} else {
					stepResult.Status = result.StatusFailed
					stepResult.StatusMessage = "FAILED!"
				}
			} else {
				stepResult.Status = result.StatusFailed
				stepResult.StatusMessage = "FAILED!"
				err = fmt.Errorf("Something is wrong with the private Key. Unable to assert the private key into an RSA PrivateKey Type. Check the data format input (Should be DER Base64 bytes) or re-download the private key")
			}
		} else {
			stepResult.Status = result.StatusFailed
			stepResult.StatusMessage = "FAILED!"
			err = fmt.Errorf("Something is wrong with the public Key. Unable to assert the public key into an RSA PublicKey Type. Check the data format input (Should be ASN.1 Base64 bytes) or re-download the public key")
		}

	} else {
		stepResult.Message = "Could not check matching of certificate and private key. Private key not provided."
		stepResult.Status = result.StatusNotChecked
		stepResult.StatusMessage = "NOT CHECKED"
	}

	return ResultData{
		Source:           SourceVerifyCertPrivateKeyMatch,
		Title:            fmt.Sprintf("Checking the certificate and private key match - %s", inputCert.Certificate.Subject.String()),
		StepResults:      []StepResultData{stepResult},
		OverallSucceeded: stepResult.Status == result.StatusSuccess || stepResult.Status == result.StatusNotChecked,
		Signature:        cmd.generateSignatureString(string(*inputCert.PemBlock)),
		Error:            err,
	}
}
