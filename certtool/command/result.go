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

// Result holds the output results of a given command
type Result struct {
	Title       string
	Source      int
	StepResults []StepResult
	Error       error
}

// StepResult holds the detailed output results that maybe in a command
type StepResult struct {
	Message       string
	Status        int
	StatusMessage string
}
