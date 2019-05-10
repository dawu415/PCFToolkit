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
			// Print the result
			for _, serverCertResult := range results {
				for _, result := range serverCertResult {
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
		}
	} else {
		fmt.Printf("ERROR: Problem encountered when running the %s command. Unable to create the command.\n", cta.CommandName)
	}

}
