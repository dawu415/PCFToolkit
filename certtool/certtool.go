package main

import (
	"fmt"
	"os"

	"github.com/dawu415/PCFToolkit/certtool/certToolArgs"
	"github.com/dawu415/PCFToolkit/certtool/certificateRepository"
	"github.com/dawu415/PCFToolkit/certtool/command"
)

func main() {
	// Get the args, process them and then pass that data to
	// a module that will determine the input action and perform the appropriate
	// execution steps.
	c := certToolArgs.NewCertToolArguments()

	cta, err := c.Process(os.Args)

	if err != nil {
		if len(err.Error()) > 0 {
			fmt.Println("ERROR: ", err.Error())
		}
	}

	if cta.PrintHelp == true {
		fmt.Println(cta.GetUsage(cta.CommandName))
		return
	}

	certRepo := certificateRepository.NewCertificateRepository()

	// Install the Root certificates
	for _, rootCertFilename := range cta.RootCAFiles {
		if err := certRepo.InstallCertificates(rootCertFilename); err != nil {
			fmt.Println("ERROR: ", err.Error())
			return
		}
	}

	// Install the Intermediate certificates
	for _, intCertFilename := range cta.IntermediateCertFiles {
		if err := certRepo.InstallCertificates(intCertFilename); err != nil {
			fmt.Println("ERROR: ", err.Error())
			return
		}
	}

	// Install the Server certificates
	for _, serverCertFileSet := range cta.ServerCertFiles {
		if err := certRepo.
			InstallCertificateWithPrivateKey(
				serverCertFileSet.ServerCertFilename,
				serverCertFileSet.ServerCertPrivateKeyFilename,
				serverCertFileSet.ServerCertPrivateKeyPassphrase); err != nil {
			fmt.Println("ERROR: ", err.Error())
			return
		}
	}
	// Create the appropriate comand and execute it.
	var cmd command.Command
	switch cta.CommandName {
	case "verify":
		cmd = command.CreateVerifyCommand(certRepo, cta.VerifyOptions.SystemDomain, cta.VerifyOptions.AppsDomain, cta.VerifyOptions.VerifyTrustChain, cta.VerifyOptions.VerifyDNS, cta.VerifyOptions.VerifyCertExpiration, cta.VerifyOptions.VerifyCertPrivateKeyMatch)
	case "decrypt":
	case "info":
		cmd = command.CreateInfoCommand(certRepo, cta.InfoOptions.FilterRootCA, cta.InfoOptions.FilterIntermediate, cta.InfoOptions.FilterServerCertificate, cta.InfoOptions.HidePEMOutput)
	default:
		fmt.Println("ERROR: Unknown Command Name - ", cta.CommandName)
	}

	var returnResult = 1

	if cmd != nil {
		results := cmd.Execute()
		if results != nil {
			results.Out()

			if results.Status() == true {
				returnResult = 0
			}
		}
	} else {
		fmt.Printf("ERROR: Problem encountered when running the %s command. Unable to create the command.\n", cta.CommandName)
	}

	os.Exit(returnResult)
}
