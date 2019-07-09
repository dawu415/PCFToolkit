package verify

import "fmt"

const (
	// SourceVerifyTrustChain is a constant describing data sourced from the verify trust chain function
	SourceVerifyTrustChain = iota
	// SourceVerifyCertSANS is a constant describing data sourced from the verify cert SANS function
	SourceVerifyCertSANS = iota
	// SourceVerifyCertExpiry is a constant describing data sourced from the verify cert expiry function
	SourceVerifyCertExpiry = iota
	// SourceVerifyCertPrivateKeyMatch is a constant describing data sourced from the verify cert private key match function
	SourceVerifyCertPrivateKeyMatch = iota
)

// Result holds a set of results from the verify command
type Result struct {
	results [][]ResultData
}

// ResultData holds the output results of the verify steps
type ResultData struct {
	Title            string
	Source           int
	StepResults      []StepResultData
	OverallSucceeded bool
	Error            error
}

// StepResultData holds the detailed output results of a verify steps
type StepResultData struct {
	Message       string
	Status        int
	StatusMessage string
}

// Out outputs data to some specific stream. Currently, it is set to output to stdout
func (result *Result) Out() {
	var results = result.results
	// Print the result
	for _, serverCertResult := range results {
		for _, result := range serverCertResult {
			if result.Error != nil {
				fmt.Println("ERROR: Unable to execute Command - Verify - ", result.Error.Error())
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

// Data returns the raw data of Result
func (result *Result) Data() interface{} {
	return result.results
}

// Status returns the overall status of the results. It takes on a worst case approach, where any failures is a failed state.
// For untested results, it is considered a success.
func (result *Result) Status() bool {
	for _, resultSet := range result.results {
		for _, result := range resultSet {
			if result.OverallSucceeded == false {
				return false
			}
		}
	}
	return true
}
