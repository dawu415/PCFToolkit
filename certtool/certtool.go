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
		fmt.Println("ERROR: ", err.Error())
		return
	} else if cta == nil {
		fmt.Println(c.GetUsage())
		return
	}

	certRepo := certificateRepository.NewCertificateRepository()

	// Install the Root certificates
	for _, rootCertFilename := range cta.RootCAFiles {
		if err := certRepo.InstallCertificates(rootCertFilename); err != nil {
			fmt.Println("ERROR: ", err.Error())
		}
	}

	// Install the Intermediate certificates
	for _, intCertFilename := range cta.IntermediateCertFiles {
		if err := certRepo.InstallCertificates(intCertFilename); err != nil {
			fmt.Println("ERROR: ", err.Error())
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
		}
	}
	// Create the appropriate comand and execute it.
	var cmd command.Command
	switch cta.CommandName {
	case "verify":
		cmd = command.CreateVerifyCommand(certRepo, cta.SystemDomain, cta.AppsDomain)
	case "decrypt":
	case "info":
	case "serve":
	default:
		fmt.Println("ERROR: Unknown Command Name - ", cta.CommandName)
	}

	results := cmd.Execute()

	// Print the result
	for _, result := range results {
		if result.Error != nil {
			fmt.Println("ERROR: Unable to execute Command - ", cmd.Name(), " - ", result.Error.Error())
		} else {
			fmt.Print("\n")
			fmt.Println("---------------------------------------------------------------------")
			fmt.Println(result.Title)
			fmt.Println("---------------------------------------------------------------------")
			for _, step := range result.StepResults {
				fmt.Println("Task: ", step.Message)
				fmt.Println("Status: ", step.StatusMessage)
			}
		}
	}

}
