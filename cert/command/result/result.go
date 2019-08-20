package result

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

// Result describes the interface to work with command results
type Result interface {
	Out()
	Data() interface{}
	Status() bool
}
