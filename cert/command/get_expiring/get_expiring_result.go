package get_expiring

import (
	"fmt"
	"strconv"
	"time"

	ResultType "github.com/dawu415/PCFToolkit/cert/command/result"
)

// Result holds a set of results from the get_expiring command
type Result struct {
	results []ResultData
	error   error
	options *Options
}

// ResultData holds the output results of the get_expiring steps
type ResultData struct {
	Filename              string
	Subject               string
	TimePeriodCheckFrom   time.Time
	TimePeriodCheckUntil  time.Time
	TimePeriodMonthLength int
	NotValidBefore        time.Time
	NotValidAfter         time.Time
	Status                int
	StatusMessage         string
	Signature             string
}

// Out outputs data to some specific stream. Currently, it is set to output to stdout
func (result *Result) Out() {
	var results = result.results

	if result.error != nil {
		fmt.Println("ERROR: Unable to execute Command - Get-Expiring - ", result.error.Error())
	}

	// Print the result
	for _, certResult := range results {
		if certResult.Status == ResultType.StatusFailed || certResult.Status == ResultType.StatusWarning || (result.options.ShowOk && certResult.Status == ResultType.StatusSuccess) {
			fmt.Print("\n")
			fmt.Println("---------------------------------------------------------------------")
			fmt.Println(certResult.Filename, " ---- ", certResult.Subject)
			fmt.Println("---------------------------------------------------------------------")
			fmt.Println("\nStatus: " + certResult.StatusMessage)
			fmt.Println("\nCertificate Valid From: " + certResult.NotValidBefore.String() + " To " + certResult.NotValidAfter.String())
			fmt.Println("\nTime Check Period Length: " + strconv.Itoa(certResult.TimePeriodMonthLength) + " Months")
			fmt.Println("Time Check Period From: " + certResult.TimePeriodCheckFrom.String())
			fmt.Println("Time Check Period To: " + certResult.TimePeriodCheckFrom.String())
			fmt.Println("\nCert Signature: " + certResult.Signature)
		}
	}
}

// Data returns the raw data of Result
func (result *Result) Data() interface{} {
	return result.results
}

// Status returns the overall status of the results. It takes on a worst case approach, where any failures is a failed state.
// For untested results, it is considered a success.
func (result *Result) Status() bool {
	for _, result := range result.results {
		if result.Status == ResultType.StatusFailed {
			return false
		}
	}
	return true
}
