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
		if len(serverCertFileSet.ServerCertFilename) != 0 {
			if err := certRepo.
				InstallCertificateWithPrivateKey(
					serverCertFileSet.ServerCertFilename,
					serverCertFileSet.ServerCertPrivateKeyFilename,
					serverCertFileSet.ServerCertPrivateKeyPassphrase); err != nil {
				fmt.Println("ERROR: ", err.Error())
				return
			}
		} else {
			// Special case if the server certificate wasn't provided but only the private key
			// This is used for the decryption command
			if err := certRepo.
				InstallPrivateKey(
					serverCertFileSet.ServerCertPrivateKeyFilename,
					serverCertFileSet.ServerCertPrivateKeyFilename,
					serverCertFileSet.ServerCertPrivateKeyPassphrase); err != nil {
				fmt.Println("ERROR: ", err.Error())
				return
			}
		}
	}
	// Create the appropriate comand and execute it.
	var cmd command.Command
	switch cta.CommandName {
	case "verify":
		cmd = command.CreateVerifyCommand(certRepo, cta.SystemDomain, cta.AppsDomain)
	case "decrypt":
	case "info":
		cmd = command.CreateInfoCommand(certRepo)
	default:
		fmt.Println("ERROR: Unknown Command Name - ", cta.CommandName)
	}

	if cmd != nil {
		results := cmd.Execute()
		if results != nil {
			results.Out()
		}
	} else {
		fmt.Printf("ERROR: Problem encountered when running the %s command. Unable to create the command.\n", cta.CommandName)
	}

}
