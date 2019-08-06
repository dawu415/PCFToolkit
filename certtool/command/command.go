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
func CreateVerifyCommand(certRepo *certificateRepository.CertificateRepository, verifyOptions *verify.Options) Command {
	return verify.NewVerifyCommand(certRepo, verifyOptions)
}

// CreateInfoCommand creates an Info Command
func CreateInfoCommand(certRepo *certificateRepository.CertificateRepository, infoOptions *info.Options) Command {
	return info.NewInfoCommand(certRepo, infoOptions)
}
