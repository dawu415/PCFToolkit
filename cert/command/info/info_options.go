package info

// Options hold the information for optional input flags for the Info Commandå
type Options struct {
	FilterRootCA            bool
	FilterIntermediate      bool
	FilterServerCertificate bool
	HidePEMOutput           bool
	ContainsFilter          string
}
