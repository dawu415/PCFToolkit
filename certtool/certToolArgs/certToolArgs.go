package certToolArgs

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
)

// Interface describes the interface to process input commandline arguments
type Interface interface {
	Process(args []string) (*CertToolArguments, error)
	GetUsage() string
}

// CSPFlagProperty defines a flag in create-service-push, its properties and a handler to decode output to a CSPArgument struct
type certToolFlagProperty struct {
	description   string
	argumentCount int
	handler       func(int, []string, int, *CertToolArguments, *error) // func(index, argument list, argCount, outputArgument, error)
}

// CertToolCertificateFileSet describes a server certificate having a corresponding private key filename and a passphrase, if it is encrypted.
type CertToolCertificateFileSet struct {
	ServerCertFilename             string
	ServerCertPrivateKeyFilename   string
	ServerCertPrivateKeyPassphrase string
}

// CertToolArguments holds the Processed input arguments
type CertToolArguments struct {
	programName           string
	CommandName           string // Describes the Command that is to be run in the program.  Possible values:  verify, decrypt, info and serve
	FindRootCA            bool
	RootCAFiles           []string
	IntermediateCertFiles []string
	ServerCertFiles       []CertToolCertificateFileSet
	SystemDomain          string
	AppsDomain            string
	flags                 map[string]*certToolFlagProperty // Private variable
}

// NewCertToolArguments returns an initialized certToolArguments struct
func NewCertToolArguments() *CertToolArguments {
	return &CertToolArguments{
		programName:           filepath.Base(os.Args[0]),
		RootCAFiles:           []string{},
		FindRootCA:            false,
		IntermediateCertFiles: []string{},
		ServerCertFiles:       []CertToolCertificateFileSet{},
		SystemDomain:          "sys.",
		AppsDomain:            "apps.",

		flags: map[string]*certToolFlagProperty{
			/////////////////////////////////////////////////
			"--server-cert": &certToolFlagProperty{
				description:   "Takes in a server certificate filename and optionally, its private key filename and/or its passphrase. Separated by spaces. The format is --server-cert server.crt [server.key [passphrase]]",
				argumentCount: 1,
				handler: func(index int, args []string, argCount int, cta *CertToolArguments, err *error) {
					*err = nil
					if (index + 1) < len(args) { // This condition covers the case if we don't have any arguments at the end of the arg list
						// This flag has a variable number of arguments
						// Count the number of arguments until it reaches a '-'
						var idx = index
						for idx = index + 1; idx < len(args); idx++ {
							if strings.HasPrefix(args[idx], "-") {
								break
							}
						}

						// Calculate the number of arguments
						argCount = idx - index - 1
						// Update the argument count
						cta.flags["--server-cert"].argumentCount = argCount

						cert := CertToolCertificateFileSet{}

						if argCount > 0 {
							if argCount >= 1 {
								cert.ServerCertFilename = args[index+1]
							}

							if argCount >= 2 {
								cert.ServerCertPrivateKeyFilename = args[index+2]
							}

							if argCount >= 3 {
								cert.ServerCertPrivateKeyPassphrase = args[index+3]
							}
							cta.ServerCertFiles = append(cta.ServerCertFiles, cert)
						} else {
							*err = fmt.Errorf("No arguments provided for --server-cert. Got %s instead", args[index+1])
						}
					} else {
						*err = fmt.Errorf("No arguments provided for --server-cert")
					}
				},
			},
			/////////////////////////////////////////////////
			"--cert": &certToolFlagProperty{
				description:   "Takes in a certificate filename containing one or more certificates. The format is --cert cert.pem",
				argumentCount: 1,
				handler: func(index int, args []string, argCount int, cta *CertToolArguments, err *error) {
					*err = nil
					if (index + argCount) < len(args) {
						// For simplicity of code, lets not be generic and just assume the
						// code here has the argument count of 1.
						if !strings.HasPrefix(args[index+1], "-") {
							cta.IntermediateCertFiles = append(cta.IntermediateCertFiles, args[index+1])
						} else {
							*err = fmt.Errorf("No arguments provided for --cert. Got %s instead", args[index+1])
						}
					} else {
						*err = fmt.Errorf("No arguments provided for --cert")
					}
				},
			},
			/////////////////////////////////////////////////
			"--find-root-ca": &certToolFlagProperty{
				description:   "Flag with no arguments used to specify the need to output the root ca certificate. ",
				argumentCount: 0,
				handler: func(index int, args []string, argCount int, cta *CertToolArguments, err *error) {
					*err = nil
					cta.FindRootCA = true
				},
			},
			/////////////////////////////////////////////////
			"--root-ca": &certToolFlagProperty{
				description:   "Takes in a root ca certificate.  If specified, this will be used as the trusted CA for the input certificate. Otherwise, the system trusted certs are used instead. Usage: --root-ca rootca.pem",
				argumentCount: 1,
				handler: func(index int, args []string, argCount int, cta *CertToolArguments, err *error) {
					*err = nil
					if (index + argCount) < len(args) {
						// For simplicity of code, lets not be generic and just assume the
						// code here has the argument count of 1.
						if !strings.HasPrefix(args[index+1], "-") {
							cta.RootCAFiles = append(cta.RootCAFiles, args[index+1])
						} else {
							*err = fmt.Errorf("No arguments provided for --root-ca. Got %s instead", args[index+1])
						}
					} else {
						*err = fmt.Errorf("No arguments provided for --root-ca")
					}
				},
			},
			/////////////////////////////////////////////////
			"--private-key": &certToolFlagProperty{
				description:   "Takes in a private key file and potentially, its decryption passphrase.  --private-key server.key[,passphrase]",
				argumentCount: 1,
				handler: func(index int, args []string, argCount int, cta *CertToolArguments, err *error) {
					*err = nil
					if (index + argCount) < len(args) {
						// For simplicity of code, lets not be generic and just assume the
						// code here has the argument count of 1.
						if !strings.HasPrefix(args[index+1], "-") {
							input := strings.SplitN(args[index+1], ",", 2)

							cert := CertToolCertificateFileSet{}
							if len(input) >= 1 {
								cert.ServerCertPrivateKeyFilename = input[0]
							}

							if len(input) >= 2 {
								cert.ServerCertPrivateKeyPassphrase = input[1]
							}
							cta.ServerCertFiles = append(cta.ServerCertFiles, cert)
						} else {
							*err = fmt.Errorf("No arguments provided for --private-key. Got %s instead", args[index+1])
						}
					} else {
						*err = fmt.Errorf("No arguments provided for --private-key")
					}
				},
			},
			/////////////////////////////////////////////////
			"--apps-domain": &certToolFlagProperty{
				description:   "Specifies the app domain on PCF, e.g., apps.company.com . This should be the subdomain. Defaults to 'apps.'",
				argumentCount: 1,
				handler: func(index int, args []string, argCount int, cta *CertToolArguments, err *error) {
					*err = nil
					if (index + argCount) < len(args) {
						if !strings.HasPrefix(args[index+1], "-") {
							cta.AppsDomain = args[index+1]
							if !strings.HasSuffix(cta.AppsDomain, ".") {
								cta.AppsDomain = cta.AppsDomain + "."
							}
						} else {
							*err = fmt.Errorf("No arguments provided for --apps-domain. Got %s instead", args[index+1])
						}
					} else {
						*err = fmt.Errorf("No arguments provided for --apps-domain")
					}
				},
			},
			/////////////////////////////////////////////////
			"--sys-domain": &certToolFlagProperty{
				description:   "Specifies the sys domain on PCF, e.g., sys.company.com . This should be the subdomain. Defaults to 'sys.'",
				argumentCount: 1,
				handler: func(index int, args []string, argCount int, cta *CertToolArguments, err *error) {
					*err = nil
					if (index + argCount) < len(args) {
						if !strings.HasPrefix(args[index+1], "-") {
							cta.SystemDomain = args[index+1]
							if !strings.HasSuffix(cta.SystemDomain, ".") {
								cta.SystemDomain = cta.SystemDomain + "."
							}
						} else {
							*err = fmt.Errorf("No arguments provided for --sys-domain. Got %s instead", args[index+1])
						}
					} else {
						*err = fmt.Errorf("No arguments provided for --sys-domain")
					}
				},
			},
		},
	}
}

// GetUsage returns the usage instruction text to display when help is called.
func (cta *CertToolArguments) GetUsage() string {
	var sb strings.Builder
	var usageString = `Usage: %s [COMMAND] [--server-cert FILENAME [PRIVATE_KEY_FILENAME [PRIVATE_KEY_PASSPHRASE]]]...
                          [--apps-domain APP_SUBDOMAIN] [--sys-domain SYS_SUBDOMAIN]
                          [--cert FILENAME]... [--root-ca FILENAME]... [--find-root-ca]

     COMMAND: A specific command that this program will run. Possible values include:
         1) verify  - Performs a set of certificate tests to ensure it is suitable for use on PCF
         2) info    - Provides specific information on the certicate inputs
         3) serve   - Create an HTTPS listener using a specific certificate input
         4) decrypt - Decrypts a given private key with its corresponding passphrase

     FLAGS:`
	sb.WriteRune('\n')
	sb.WriteString(fmt.Sprintf(usageString, cta.programName))

	sb.WriteRune('\n')

	w := tabwriter.NewWriter(&sb, 0, 0, 2, ' ', 0)
	for flag, property := range cta.flags {
		fmt.Fprintf(w, "     %s:\t%s\n", flag, property.description)
	}

	w.Flush()

	return sb.String()
}

// Process function is the entrypoint for processing certtool Arguments
func (cta *CertToolArguments) Process(args []string) (*CertToolArguments, error) {

	args = args[1:] // Remove the first executable name

	// If there were no other arguments, we can short circuit the Process method
	// Let the caller handle the state if the arguments are nil
	if len(args) == 0 {
		return nil, nil
	}

	// Determine the command type
	cta.CommandName = args[0]
	args = args[1:] // remove the CommandName and leave only the flags to process

	// Validate the command
	if (cta.CommandName != "verify") &&
		(cta.CommandName != "decrypt") &&
		(cta.CommandName != "info") &&
		(cta.CommandName != "serve") {
		return nil, fmt.Errorf("Unknown command: %s", cta.CommandName)
	}

	if len(args) == 0 {
		return nil, nil
	}

	var err error
	// Iterate through the possible set of arguments to see if they're in the args list
	for idx := 0; idx < len(args); idx++ {
		arg := args[idx]
		if property, isCTAFlag := cta.flags[arg]; isCTAFlag {
			property.handler(idx, args, property.argumentCount, cta, &err)
			idx += property.argumentCount
		} else {
			err = fmt.Errorf("Unknown flag encountered: %s", args[idx])
		}

		if err != nil {
			break
		}
	}

	return cta, err
}
