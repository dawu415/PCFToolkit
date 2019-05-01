package command

import "github.com/dawu415/PCFToolkit/certtool/certificateRepository"

// Command describes the interface to start running a command
type Command interface {
	Execute() [][]Result
	Name() string
}

// CreateVerifyCommand creates a Verify Command
func CreateVerifyCommand(certRepo *certificateRepository.CertificateRepository, systemDomain, appDomain string) Command {
	return NewVerifyCommand(certRepo, systemDomain, appDomain)
}

// CreateInfoCommand creates an Info Command
func CreateInfoCommand(certRepo *certificateRepository.CertificateRepository) Command {
	return NewInfoCommand(certRepo)
}
