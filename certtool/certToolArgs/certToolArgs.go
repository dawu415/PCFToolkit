package certToolArgs

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	Info "github.com/dawu415/PCFToolkit/certtool/command/info"
	"github.com/olekukonko/tablewriter"
)

// COMMANDS is the list of supported commands in this application
var COMMANDS = map[string]string{
	"verify": "Performs a set of certificate tests to ensure it is suitable for use on PCF",
	"info":   "Provides specific information on the certicate inputs",
	//"decrypt": "Decrypts a given private key with its corresponding passphrase",
}

// Interface describes the interface to process input commandline arguments
type Interface interface {
	Process(args []string) (*CertToolArguments, error)
	GetUsage() string
}

// certToolFlagProperty defines a flag for the cert tool
type certToolFlagProperty struct {
	description        string
	argumentCount      int
	compatibleCommands []string
	handler            func(int, []string, int, *CertToolArguments, []string, *error) // func(index, argument list, argCount, outputArgument,compatibleCommands, error)
}

// CertToolCertificateFileSet describes a server certificate having a corresponding private key filename and a passphrase, if it is encrypted.
type CertToolCertificateFileSet struct {
	ServerCertFilename             string
	ServerCertPrivateKeyFilename   string
	ServerCertPrivateKeyPassphrase string
}

// VerifyOptions hold the information for optional input flags for the Verify Commandå
type VerifyOptions struct {
	SystemDomain                 string
	AppsDomain                   string
	VerifyTrustChain             bool
	VerifyDNS                    bool
	VerifyCertExpiration         bool
	VerifyCertPrivateKeyMatch    bool
	ContainsFilter               string
	MinimumMonthsWarningToExpire int
}

// CertificateYMLFiles contains the path to the yml file and a string that holds the internal path to the certificate field
type CertificateYMLFiles struct {
	YMLFilename string
	YMLPath     string
}

// CertToolArguments holds the Processed input arguments
type CertToolArguments struct {
	programName           string
	CommandName           string // Describes the Command that is to be run in the program.
	RootCAFiles           []string
	IntermediateCertFiles []string
	ServerCertFiles       []CertToolCertificateFileSet
	VerifyOptions         VerifyOptions
	InfoOptions           Info.Options
	CertificateYMLFiles   []CertificateYMLFiles
	flags                 map[string]*certToolFlagProperty // Private variable
	PrintHelp             bool
}

// NewCertToolArguments returns an initialized certToolArguments struct
// For new flags, add them to this map of flags here.
func NewCertToolArguments() *CertToolArguments {
	return &CertToolArguments{
		programName:           filepath.Base(os.Args[0]),
		RootCAFiles:           []string{},
		IntermediateCertFiles: []string{},
		ServerCertFiles:       []CertToolCertificateFileSet{},
		CertificateYMLFiles:   []CertificateYMLFiles{},

		VerifyOptions: VerifyOptions{
			SystemDomain:                 "sys.",
			AppsDomain:                   "apps.",
			MinimumMonthsWarningToExpire: 6,
		},
		InfoOptions: Info.Options{},

		flags: map[string]*certToolFlagProperty{
			/////////////////////////////////////////////////
			"--server-cert": &certToolFlagProperty{
				description:        "Takes in a server certificate filename and optionally, its unencrypted private key filename. Separated by spaces. The format is --server-cert <server.crt> [<server.key>]",
				argumentCount:      1,
				compatibleCommands: []string{"verify", "info"},
				handler: func(index int, args []string, argCount int, cta *CertToolArguments, compatibleCmds []string, err *error) {
					*err = nil

					if cta.IsCurrentCommandSupported(compatibleCmds) {
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
					} else {
						*err = fmt.Errorf("%s does not support --server-cert", cta.CommandName)
					}
				},
			},
			/////////////////////////////////////////////////
			"--cert": &certToolFlagProperty{
				description:        "Takes in a certificate filename containing one or more certificates. The format is --cert <cert.pem>",
				argumentCount:      1,
				compatibleCommands: []string{"verify", "info"},
				handler: func(index int, args []string, argCount int, cta *CertToolArguments, compatibleCmds []string, err *error) {
					*err = nil
					if cta.IsCurrentCommandSupported(compatibleCmds) {
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
					} else {
						*err = fmt.Errorf("%s does not support --cert", cta.CommandName)
					}
				},
			},
			/////////////////////////////////////////////////
			"--cert-yml-field": &certToolFlagProperty{
				description:        "Takes in a certificate yml filename and path to certificates. The format is --cert-yml-field <file.yml> </path/to/cert>",
				argumentCount:      2,
				compatibleCommands: []string{"verify", "info"},
				handler: func(index int, args []string, argCount int, cta *CertToolArguments, compatibleCmds []string, err *error) {
					*err = nil
					if cta.IsCurrentCommandSupported(compatibleCmds) {
						if (index + argCount) < len(args) {
							if !strings.HasPrefix(args[index+1], "-") {
								filename := args[index+1]

								var ymlPath string
								if !strings.HasPrefix(args[index+2], "-") {
									ymlPath = args[index+2]
									cta.CertificateYMLFiles = append(cta.CertificateYMLFiles,
										CertificateYMLFiles{YMLFilename: filename, YMLPath: ymlPath})
								} else {
									*err = fmt.Errorf("Invalid arguments provided for --cert-yml-field. Got %s instead", args[index+2])
								}
							} else {
								*err = fmt.Errorf("No arguments provided for --cert-yml-field. Got %s instead", args[index+1])
							}
						} else {
							*err = fmt.Errorf("No arguments provided for --cert-yml-field")
						}
					} else {
						*err = fmt.Errorf("%s does not support --cert", cta.CommandName)
					}
				},
			},
			/////////////////////////////////////////////////
			"--root-ca": &certToolFlagProperty{
				description:        "Takes in a root ca certificate.  If specified, this will be used as the trusted CA for the input certificate. Otherwise, the system trusted certs are used instead. Usage: --root-ca <rootca.pem>",
				argumentCount:      1,
				compatibleCommands: []string{"verify", "info"},
				handler: func(index int, args []string, argCount int, cta *CertToolArguments, compatibleCmds []string, err *error) {
					*err = nil
					if cta.IsCurrentCommandSupported(compatibleCmds) {
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
					} else {
						*err = fmt.Errorf("%s does not support --root-ca", cta.CommandName)
					}
				},
			},
			/////////////////////////////////////////////////
			"--private-key": &certToolFlagProperty{
				description:        "Takes in a private key file and potentially, its decryption passphrase - if encrypted.  --private-key server.key[,passphrase]",
				argumentCount:      1,
				compatibleCommands: []string{"decrypt"},
				handler: func(index int, args []string, argCount int, cta *CertToolArguments, compatibleCmds []string, err *error) {
					*err = nil
					if cta.IsCurrentCommandSupported(compatibleCmds) {
						if (index + argCount) < len(args) {
							// For simplicity of code, lets not be generic and just assume the
							// code here has the argument count of 1.
							if !strings.HasPrefix(args[index+1], "-") { // if the user did not input any arguments for --private-key
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
					} else {
						*err = fmt.Errorf("%s does not support --private-key", cta.CommandName)
					}
				},
			},
			/////////////////////////////////////////////////
			"--apps-domain": &certToolFlagProperty{
				description:        "Specifies the app domain on PCF, e.g., apps.company.com . This should be the subdomain. Defaults to 'apps.'",
				argumentCount:      1,
				compatibleCommands: []string{"verify"},
				handler: func(index int, args []string, argCount int, cta *CertToolArguments, compatibleCmds []string, err *error) {
					*err = nil
					if cta.IsCurrentCommandSupported(compatibleCmds) {
						if (index + argCount) < len(args) {
							if !strings.HasPrefix(args[index+1], "-") {
								cta.VerifyOptions.AppsDomain = args[index+1]
							} else {
								*err = fmt.Errorf("No arguments provided for --apps-domain. Got %s instead", args[index+1])
							}
						} else {
							*err = fmt.Errorf("No arguments provided for --apps-domain")
						}
					} else {
						*err = fmt.Errorf("%s does not support --apps-domain", cta.CommandName)
					}
				},
			},
			/////////////////////////////////////////////////
			"--sys-domain": &certToolFlagProperty{
				description:        "Specifies the sys domain on PCF, e.g., sys.company.com . This should be the subdomain. Defaults to 'sys.'",
				argumentCount:      1,
				compatibleCommands: []string{"verify"},
				handler: func(index int, args []string, argCount int, cta *CertToolArguments, compatibleCmds []string, err *error) {
					*err = nil
					if cta.IsCurrentCommandSupported(compatibleCmds) {
						if (index + argCount) < len(args) {
							if !strings.HasPrefix(args[index+1], "-") {
								cta.VerifyOptions.SystemDomain = args[index+1]
							} else {
								*err = fmt.Errorf("No arguments provided for --sys-domain. Got %s instead", args[index+1])
							}
						} else {
							*err = fmt.Errorf("No arguments provided for --sys-domain")
						}
					} else {
						*err = fmt.Errorf("%s does not support --sys-domain", cta.CommandName)
					}
				},
			},
			/////////////////////////////////////////////////
			"--verify-trust-chain": &certToolFlagProperty{
				description:        "Runs the verify command only for determining the trust chain",
				argumentCount:      0,
				compatibleCommands: []string{"verify"},
				handler: func(index int, args []string, argCount int, cta *CertToolArguments, compatibleCmds []string, err *error) {
					*err = nil
					if cta.IsCurrentCommandSupported(compatibleCmds) {
						cta.VerifyOptions.VerifyTrustChain = true
					} else {
						*err = fmt.Errorf("%s does not support --verify-trust-chain", cta.CommandName)
					}
				},
			},
			/////////////////////////////////////////////////
			"--verify-dns": &certToolFlagProperty{
				description:        "Runs the verify command only for determining the DNS/SANs in Certificate",
				argumentCount:      0,
				compatibleCommands: []string{"verify"},
				handler: func(index int, args []string, argCount int, cta *CertToolArguments, compatibleCmds []string, err *error) {
					*err = nil
					if cta.IsCurrentCommandSupported(compatibleCmds) {
						cta.VerifyOptions.VerifyDNS = true
					} else {
						*err = fmt.Errorf("%s does not support --verify-dns", cta.CommandName)
					}
				},
			},
			/////////////////////////////////////////////////
			"--verify-cert-expiration": &certToolFlagProperty{
				description:        "Runs the verify command only for determing expiration (or within 6 months) of a Certificate",
				argumentCount:      0,
				compatibleCommands: []string{"verify"},
				handler: func(index int, args []string, argCount int, cta *CertToolArguments, compatibleCmds []string, err *error) {
					*err = nil
					if cta.IsCurrentCommandSupported(compatibleCmds) {
						cta.VerifyOptions.VerifyCertExpiration = true
					} else {
						*err = fmt.Errorf("%s does not support --verify-trust-expiration", cta.CommandName)
					}
				},
			},
			/////////////////////////////////////////////////
			"--verify-cert-private-key-match": &certToolFlagProperty{
				description:        "Runs the verify command only for determing whether a private key matches a Certificate",
				argumentCount:      0,
				compatibleCommands: []string{"verify"},
				handler: func(index int, args []string, argCount int, cta *CertToolArguments, compatibleCmds []string, err *error) {
					*err = nil
					if cta.IsCurrentCommandSupported(compatibleCmds) {
						cta.VerifyOptions.VerifyCertPrivateKeyMatch = true
					} else {
						*err = fmt.Errorf("%s does not support --verify-cert-private-key-match", cta.CommandName)
					}
				},
			},
			/////////////////////////////////////////////////
			"--filter-on-root": &certToolFlagProperty{
				description:        "Filter the info command output to show root CA certificates",
				argumentCount:      0,
				compatibleCommands: []string{"info"},
				handler: func(index int, args []string, argCount int, cta *CertToolArguments, compatibleCmds []string, err *error) {
					*err = nil
					if cta.IsCurrentCommandSupported(compatibleCmds) {
						cta.InfoOptions.FilterRootCA = true
					} else {
						*err = fmt.Errorf("%s does not support --filter-on-root", cta.CommandName)
					}
				},
			},
			/////////////////////////////////////////////////
			"--filter-on-intermediate": &certToolFlagProperty{
				description:        "Filter the info command output to show intermediate certificates",
				argumentCount:      0,
				compatibleCommands: []string{"info"},
				handler: func(index int, args []string, argCount int, cta *CertToolArguments, compatibleCmds []string, err *error) {
					*err = nil
					if cta.IsCurrentCommandSupported(compatibleCmds) {
						cta.InfoOptions.FilterIntermediate = true
					} else {
						*err = fmt.Errorf("%s does not support --filter-on-intermediate", cta.CommandName)
					}
				},
			},
			/////////////////////////////////////////////////
			"--filter-on-server": &certToolFlagProperty{
				description:        "Filter the info command output to show server certificates",
				argumentCount:      0,
				compatibleCommands: []string{"info"},
				handler: func(index int, args []string, argCount int, cta *CertToolArguments, compatibleCmds []string, err *error) {
					*err = nil
					if cta.IsCurrentCommandSupported(compatibleCmds) {
						cta.InfoOptions.FilterServerCertificate = true
					} else {
						*err = fmt.Errorf("%s does not support --filter-on-server", cta.CommandName)
					}
				},
			},
			/////////////////////////////////////////////////
			"--hide-pem": &certToolFlagProperty{
				description:        "Hide PEM blocks in the info command output",
				argumentCount:      0,
				compatibleCommands: []string{"info"},
				handler: func(index int, args []string, argCount int, cta *CertToolArguments, compatibleCmds []string, err *error) {
					*err = nil
					if cta.IsCurrentCommandSupported(compatibleCmds) {
						cta.InfoOptions.HidePEMOutput = true
					} else {
						*err = fmt.Errorf("%s does not support --hide-pem", cta.CommandName)
					}
				},
			},
			/////////////////////////////////////////////////
			"--expire-warning-time": &certToolFlagProperty{
				description:        "Specify the minimum number of months to warn that a certificate will expire. defaults: 6 months",
				argumentCount:      1,
				compatibleCommands: []string{"verify"},
				handler: func(index int, args []string, argCount int, cta *CertToolArguments, compatibleCmds []string, err *error) {
					*err = nil
					if cta.IsCurrentCommandSupported(compatibleCmds) {
						if (index + argCount) < len(args) {
							if !strings.HasPrefix(args[index+1], "-") {
								var value int
								value, *err = strconv.Atoi(args[index+1])
								if *err == nil {
									cta.VerifyOptions.MinimumMonthsWarningToExpire = value
								}
							} else {
								*err = fmt.Errorf("No arguments provided for --expire-warning-time. Got %s instead", args[index+1])
							}
						} else {
							*err = fmt.Errorf("No arguments provided for --expire-warning-time")
						}
					} else {
						*err = fmt.Errorf("%s does not support --expire-warning-time", cta.CommandName)
					}
				},
			},
			/////////////////////////////////////////////////
			"--name": &certToolFlagProperty{
				description:        "Employs 'contains' string filtering on subject Common Name or SANs of certificate",
				argumentCount:      1,
				compatibleCommands: []string{"info", "verify"},
				handler: func(index int, args []string, argCount int, cta *CertToolArguments, compatibleCmds []string, err *error) {
					*err = nil
					if cta.IsCurrentCommandSupported(compatibleCmds) {
						if (index + argCount) < len(args) {
							if !strings.HasPrefix(args[index+1], "-") {
								if cta.CommandName == "info" {
									cta.InfoOptions.ContainsFilter = args[index+1]
								} else if cta.CommandName == "verify" {
									cta.VerifyOptions.ContainsFilter = args[index+1]
								}
							} else {
								*err = fmt.Errorf("No arguments provided for --name. Got %s instead", args[index+1])
							}
						} else {
							*err = fmt.Errorf("No arguments provided for --name")
						}
					} else {
						*err = fmt.Errorf("%s does not support --name", cta.CommandName)
					}
				},
			},
			/////////////////////////////////////////////////
			"--help": &certToolFlagProperty{
				description:        "",
				argumentCount:      0,
				compatibleCommands: []string{""},
				handler: func(index int, args []string, argCount int, cta *CertToolArguments, compatibleCmds []string, err *error) {
					*err = nil
					cta.PrintHelp = true
				},
			},
		},
	}
}

// IsCurrentCommandSupported checks if the current command is supported by a given list of commands.
func (cta *CertToolArguments) IsCurrentCommandSupported(compatibleCommands []string) bool {
	var isSupported = false
	for _, supportedCommand := range compatibleCommands {
		if cta.CommandName == supportedCommand {
			isSupported = true
			break
		}
	}
	return isSupported
}

// GetUsage returns the usage instruction text to display when help is called.
func (cta *CertToolArguments) GetUsage(commandToRun string) string {
	var sb strings.Builder
	var usageString = `Usage: %s COMMAND [--help] [FLAG1...FLAGn]`

	sb.WriteString(fmt.Sprintf(usageString, cta.programName))
	sb.WriteRune('\n')
	sb.WriteRune('\n')
	tbl := tablewriter.NewWriter(&sb)
	sb.WriteString("  COMMAND: A specific command that this program will run. Possible values include:\n\n")
	tbl.SetBorder(false)
	tbl.SetColWidth(120)
	tbl.SetColumnSeparator(" ")
	tableData := [][]string{}
	for cmd, description := range COMMANDS {
		tableData = append(tableData, []string{cmd + ":", description})
	}

	tbl.AppendBulk(tableData)
	tbl.Render()

	sb.WriteRune('\n')
	if _, ok := COMMANDS[commandToRun]; len(commandToRun) > 0 && ok {
		sb.WriteString("Supported Flags:\n\n")

		tbl := tablewriter.NewWriter(&sb)

		tbl.SetBorder(false)
		tbl.SetColWidth(120)
		tableData := [][]string{}
		for flag, property := range cta.flags {
			for _, supportedCommand := range property.compatibleCommands {
				if commandToRun == supportedCommand {
					tableData = append(tableData, []string{flag, property.description})
					break
				}
			}
		}

		tbl.AppendBulk(tableData)
		tbl.Render()
	} else {
		sb.WriteString("	 input --help after a command to get details about its flags\n")
	}

	return sb.String()
}

// Process function is the entrypoint for processing certtool Arguments
func (cta *CertToolArguments) Process(args []string) (*CertToolArguments, error) {

	args = args[1:] // Remove the first executable name

	// If there were no other arguments, we can short circuit the Process method
	// Let the caller handle the state if the arguments are nil
	if len(args) == 0 {
		cta.PrintHelp = true
		return cta, nil
	}

	// Determine the command type
	cta.CommandName = args[0]
	args = args[1:] // remove the CommandName and leave only the flags to process

	// Validate the command
	if _, ok := COMMANDS[cta.CommandName]; !ok {
		cta.PrintHelp = true
		err := fmt.Errorf("Unknown command: %s", cta.CommandName)
		cta.CommandName = ""
		return cta, err
	}

	if len(args) == 0 {
		cta.PrintHelp = true
		return cta, nil
	}

	var err error
	// Iterate through the possible set of arguments to see if they're in the args list
	for idx := 0; idx < len(args); idx++ {
		arg := args[idx]
		if property, isCTAFlag := cta.flags[arg]; isCTAFlag {
			property.handler(idx, args, property.argumentCount, cta, property.compatibleCommands, &err)
			idx += property.argumentCount
		} else {
			cta.PrintHelp = true
			err = fmt.Errorf("Unknown flag encountered: %s", args[idx])
		}

		if err != nil {
			break
		}
	}

	return cta, err
}
