package command

import (
	"github.com/dawu415/PCFToolkit/certtool/certificateRepository"
	"github.com/dawu415/PCFToolkit/certtool/command/info"
	"github.com/dawu415/PCFToolkit/certtool/command/result"
	"github.com/dawu415/PCFToolkit/certtool/command/verify"
)

// Command describes the interface to start running a command
type Command interface {
	Execute() result.Result
	Name() string
}

// CreateVerifyCommand creates a Verify Command
func CreateVerifyCommand(certRepo *certificateRepository.CertificateRepository, systemDomain, appDomain string, verifyTrustChain, verifyDNS, verifyCertExpiration, verifyCertPrivateKeyMatch bool) Command {
	return verify.NewVerifyCommand(certRepo, systemDomain, appDomain, verifyTrustChain, verifyDNS, verifyCertExpiration, verifyCertPrivateKeyMatch)
}

// CreateInfoCommand creates an Info Command
func CreateInfoCommand(certRepo *certificateRepository.CertificateRepository) Command {
	return info.NewInfoCommand(certRepo)
}
