package command

const (
	StatusSuccess    = iota
	StatusWarning    = iota
	StatusFailed     = iota
	StatusNotChecked = iota
)

type Result struct {
	Title       string
	StepResults []StepResult
	Error       error
}

type StepResult struct {
	Source        string
	Message       string
	Status        int
	StatusMessage string
}
