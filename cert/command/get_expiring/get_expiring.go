package get_expiring

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/dawu415/PCFToolkit/cert/command/result"

	"github.com/dawu415/PCFToolkit/cert/command/x509Lib"

	"github.com/dawu415/PCFToolkit/cert/certificateRepository/certificate"

	"github.com/dawu415/PCFToolkit/cert/certificateRepository"
)

// GetExpiring defines the struct holding the data necessary to execute a command
type GetExpiring struct {
	certRepo *certificateRepository.CertificateRepository
	options  *Options
	x509Lib  x509Lib.Interface
}

// NewGetExpiringCommand creates a new get-expiring command with a given certificate respository
func NewGetExpiringCommand(certRepo *certificateRepository.CertificateRepository, getExpiringOptions *Options) *GetExpiring {
	return NewGetExpiringCommandCustomGetExpiringLib(certRepo, getExpiringOptions, x509Lib.NewX509Lib())
}

// NewGetExpiringCommandCustomGetExpiringLib returns a get-expiring command with given certificate repository and an x509VerifyLib
func NewGetExpiringCommandCustomGetExpiringLib(certRepo *certificateRepository.CertificateRepository, getExpiringOptions *Options, getExpiringLib x509Lib.Interface) *GetExpiring {
	return &GetExpiring{
		certRepo: certRepo,
		options:  getExpiringOptions,
		x509Lib:  getExpiringLib,
	}
}

// Name describes the name of this command
func (cmd *GetExpiring) Name() string {
	return "Get-Expiring"
}

// Execute performs the command
func (cmd *GetExpiring) Execute() result.Result {
	var results []ResultData

	allCerts := append(append(cmd.certRepo.ServerCerts, cmd.certRepo.IntermediateCerts...), cmd.certRepo.RootCACerts...)
	certCount := len(allCerts)

	if certCount > 0 {
		results = make([]ResultData, certCount)
	}
	removeElements := []int{}
	for idx, cert := range allCerts {
		// If a contains filter exists, Only process certs whose subject or individual SANs contains the text in specified in ContainsFilter string.
		if len(cmd.options.ContainsFilter) > 0 {
			if !strings.Contains(strings.ToLower(cert.Certificate.Subject.String()), strings.ToLower(cmd.options.ContainsFilter)) &&
				!strings.Contains(strings.ToLower(strings.Join(cert.Certificate.DNSNames, " ")), strings.ToLower(cmd.options.ContainsFilter)) {
				removeElements = append(removeElements, idx)
				continue
			}
		}

		// We can verify expiration on all certificate types
		var certExpiryResult = cmd.stepCheckCertificateExpiry(cert)
		results[idx] = certExpiryResult
	}

	// Remove any skipped elements in the result set
	if len(removeElements) == len(results) {
		results = nil
	} else {
		for _, idx := range removeElements {
			results[idx] = results[len(results)-1]
			results = results[:len(results)-1]
		}
	}

	return &Result{
		results: results,
		error:   nil,
		options: cmd.options,
	}
}

// generateSignatureString generates a short output of the pem block. This will aid certificate identification
// should a filename not exist.
func (cmd *GetExpiring) generateSignatureString(pemBlock string) string {
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

// stepCheckCertificateExpiry checks the expiry of a certificate with in a 6 month period.
func (cmd *GetExpiring) stepCheckCertificateExpiry(inputCert certificate.Certificate) ResultData {

	currentTime := time.Now()

	var status int
	var statusMessage = ""
	if currentTime.After(inputCert.Certificate.NotBefore) &&
		currentTime.Before(inputCert.Certificate.NotAfter) {
		// Check if our server cert will expire within the next CertExpiryWarningMonths months.
		if currentTime.AddDate(0, cmd.options.MinimumMonthsWarningToExpire, 0).Before(inputCert.Certificate.NotAfter) {
			status = result.StatusSuccess
			statusMessage = fmt.Sprintf("OK! - This certificate expires in %0.2f days (%0.2f months)\n", inputCert.Certificate.NotAfter.Sub(currentTime).Hours()/24, inputCert.Certificate.NotAfter.Sub(currentTime).Hours()/(24*365/12))
		} else {
			status = result.StatusWarning
			statusMessage = fmt.Sprintf("WARNING - Within the next %d months, this certificate expires in %0.2f days (%0.2f months)\n", cmd.options.MinimumMonthsWarningToExpire, inputCert.Certificate.NotAfter.Sub(currentTime).Hours()/24, inputCert.Certificate.NotAfter.Sub(currentTime).Hours()/(24*365/12))
		}
	} else {
		status = result.StatusFailed
		statusMessage = "FAILED! Certificate Expired!"
	}

	return ResultData{
		Filename:              inputCert.Label,
		Subject:               inputCert.Certificate.Subject.String(),
		TimePeriodMonthLength: cmd.options.MinimumMonthsWarningToExpire,
		TimePeriodCheckFrom:   currentTime,
		TimePeriodCheckUntil:  currentTime.AddDate(0, cmd.options.MinimumMonthsWarningToExpire, 0),
		NotValidBefore:        inputCert.Certificate.NotBefore,
		NotValidAfter:         inputCert.Certificate.NotAfter,
		Status:                status,
		StatusMessage:         statusMessage,
		Signature:             cmd.generateSignatureString(string(*inputCert.PemBlock)),
	}
}
