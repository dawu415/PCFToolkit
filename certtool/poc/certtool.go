package main

import (
	"fmt"
	"os"

	"github.com/dawu415/PCFSToolkit/action"
	"github.com/dawu415/PCFSToolkit/certToolArgs"
)

func main() {
	// Get the args, process them and then pass that data to
	// a module that will determine the input action and perform the appropriate
	// execution steps.
	c := certToolArgs.NewCertToolArguments()

	cta, err := c.Process(os.Args)

	if err != nil {
		fmt.Printf("%s\n", err.Error())
	} else if cta == nil {
		fmt.Println(c.GetUsage())
	} else {
		a := action.NewAction(cta)
		err := a.Execute()
		if err != nil {
			fmt.Printf("%s\n", err.Error())
		}
	}
}
