package command

import "github.com/dawu415/PCFSToolkit/certificateRepository"

// Command describes the interface to start running a command
type Command interface {
	Execute() []Result
	Name() string
}

func CreateVerifyCommand(certRepo *certificateRepository.CertificateRepository, systemDomain, appDomain string) Command {
	return &Verify{
		certRepo:     certRepo,
		systemDomain: systemDomain,
		appsDomain:   appDomain,
	}
}
