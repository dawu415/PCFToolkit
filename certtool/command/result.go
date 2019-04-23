package command

const (
	// StatusSuccess is a constant describing a success state of a step in a command
	StatusSuccess = iota
	// StatusWarning is a constant describing a warning state of a step in a command
	StatusWarning = iota
	// StatusFailed is a constant describing a failed state of a step in a command
	StatusFailed = iota
	// StatusNotChecked is a constant describing a not checked/not performed state of a step in a command
	StatusNotChecked = iota
)

// Result holds the output results of a given command
type Result struct {
	Title       string
	StepResults []StepResult
	Error       error
}

// StepResult holds the detailed output results that maybe in a command
type StepResult struct {
	Source        string
	Message       string
	Status        int
	StatusMessage string
}
