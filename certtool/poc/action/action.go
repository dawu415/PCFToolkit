package action

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"reflect"
	"strings"
	"time"

	"github.com/asaskevich/govalidator"
	"github.com/dawu415/PCFSToolkit/certToolArgs"
	"github.com/oleiade/reflections"
)

// Interface describes the interface to process input commandline arguments
type Interface interface {
	Execute()
}

// Action defines the struct holding the data necessary to execute an action
type Action struct {
	data   *certToolArgs.CertToolArguments
	fileIO FileIOInterface
}

// certToolCert is a struct that holds a certificate and its corresponding filename
// we use this for the purpose to reference back a cert to its source file to assist
// the user in any debugging information they require
type certToolCert struct {
	sourceFilename      string
	certificate         *x509.Certificate
	privateKeyFilename  string
	privateKey          interface{}
	privateKeyEncrypted bool
}

// NewAction creates an action with a real file IO mechanism
func NewAction(args *certToolArgs.CertToolArguments) *Action {
	return &Action{
		data:   args,
		fileIO: NewFileIO(),
	}
}

// Execute processes and runs an action
func (action *Action) Execute() error {
	var err error
	// Determine the action and call the appropriate method to handle that action
	switch action.data.ActionName {
	case "test":
		err = action.executeTestAction()
	case "decrypt":
		err = action.executeDecryptAction()
	case "info":
		err = action.executeInfoAction()
	case "serve":
		err = action.executeServeAction()
	default:
		err = fmt.Errorf("Unrecognized action: %s", action.data.ActionName)
	}

	return err
}

func (action *Action) executeTestAction() error {
	// 1. I have the private key + intermediate + server cert, I would like to verify that it is correct
	//    on the basis that:
	//                    i)   It is valid and 'publicly trusted' by the OS I am running this program on and/or any certs I provide.
	//                    ii)  All DNS names are valid and listed for a PCF foundation
	//                    iii) Check the expiry of the cert. Give warning is < 6 months to go.
	//                    iv)  Check that the server cert and the private key match

	var err error
	// Sort and bin our certs into the appropriate set so that we can use it below
	rootCACerts, intermediateCerts, serverCerts, err := action.binCertificates()

	fmt.Printf("Root Certs:\t\t%+v\n", rootCACerts)
	fmt.Printf("Intermediate Certs:\t%+v\n", intermediateCerts)
	fmt.Printf("Server Certs:\t\t%+v\n", serverCerts)
	if err != nil {
		return err
	}

	// Test to see if this server cert is publicly trusted CA on our machine.
	// We need to only run this with the RootCA not set, which our x509 library will automatically
	// switch over to our machines trust store

	// Move the intermediate certs into a cert pool
	intermediateCertPool := x509.NewCertPool()

	for _, cert := range intermediateCerts {
		intermediateCertPool.AddCert(cert.certificate)
	}

	var verifyOptions x509.VerifyOptions
	fmt.Printf("\n\nValidating that the server cert is trusted on this machine:\n")
	fmt.Printf("---------------------------------------------------------------------------\n")
	verifyOptions = x509.VerifyOptions{
		Intermediates: intermediateCertPool,
		Roots:         nil, // Keep this nil, so that verify uses the system cert pool
	}

	for _, serverCert := range serverCerts {
		fmt.Printf("Verifying:\t%s\n", serverCert.sourceFilename)
		if _, certVerifyStatus := serverCert.certificate.Verify(verifyOptions); certVerifyStatus != nil {
			fmt.Printf(" ... FAILED - %s\n", certVerifyStatus.Error())
			fmt.Printf("\t\t\t Check to ensure that all certs can chain from the server to the root cert.\n")
			// TODO: Try to build a chain to assist with debugging the issue
			continue
		}
		fmt.Println("Status: OK!")
	}

	if len(rootCACerts) > 0 {
		rootCACertPool := x509.NewCertPool()
		// Move the rootCA certs into a cert pool
		for _, cert := range rootCACerts {
			rootCACertPool.AddCert(cert.certificate)
		}

		fmt.Printf("\n\nValidating that the server cert is trusted by the provided root certs\n")
		fmt.Printf("---------------------------------------------------------------------------\n")
		verifyOptions = x509.VerifyOptions{
			Intermediates: intermediateCertPool,
			Roots:         rootCACertPool, // Keep this nil, so that verify uses the system cert pool
		}
		for _, serverCert := range serverCerts {
			fmt.Printf("Verifying:\t%s\n", serverCert.sourceFilename)
			if _, certVerifyStatus := serverCert.certificate.Verify(verifyOptions); certVerifyStatus != nil {
				fmt.Printf(" ... FAILED - %s\n", certVerifyStatus.Error())
				fmt.Printf("\t\t\t Check to ensure that all certs can chain from the server to the root cert.\n")
				// TODO: Try to build a chain to assist with debugging the issue
				continue
			}
			fmt.Println("Status: OK!")
		}
	}

	fmt.Printf("\n\nValidating that the server cert contain the necessary DNS names for PCF\n")
	fmt.Printf("---------------------------------------------------------------------------\n")
	DNSNames := []string{"*." + action.data.AppsDomain,
		"*." + action.data.SystemDomain,
		"*.uaa." + action.data.SystemDomain,
		"*.login." + action.data.SystemDomain}

	for _, serverCert := range serverCerts {
		fmt.Printf("Verifying:\t%s\n", serverCert.sourceFilename)
		for _, dnsName := range DNSNames {
			fmt.Printf("%s:\t\t", dnsName)
			var found = false
			for _, dnsInCert := range serverCert.certificate.DNSNames {
				if strings.Contains(dnsInCert, dnsName) {
					found = true
					break
				}
			}

			if found {
				fmt.Printf("FOUND!\n")
			} else {
				fmt.Printf("X\n")
			}

		}
	}

	fmt.Printf("\n\nValidating the server cert expiry\n")
	fmt.Printf("---------------------------------------------------------------------------\n")
	for _, serverCert := range serverCerts {
		fmt.Printf("Verifying:\t%s\n", serverCert.sourceFilename)
		fmt.Printf("Valid From:\t%s UNTIL %s\n", serverCert.certificate.NotBefore.String(), serverCert.certificate.NotAfter.String())
		currentTime := time.Now()

		if currentTime.After(serverCert.certificate.NotBefore) &&
			currentTime.Before(serverCert.certificate.NotAfter) {
			// Check if our server cert will expire within the next 6 months.
			if currentTime.AddDate(0, 6, 0).Before(serverCert.certificate.NotAfter) {
				fmt.Println("Status: OK!")
			} else {
				fmt.Printf("Status: WARNING - This certificate expires in %0.2f days\n", serverCert.certificate.NotAfter.Sub(currentTime).Hours()/24)
			}
		} else {
			fmt.Println("Status: FAILED - This certificate has expired")
		}

	}

	fmt.Printf("\n\nValidating the server cert with its private key \n")
	fmt.Printf("---------------------------------------------------------------------------\n")
	for _, serverCert := range serverCerts {
		// If the modulus of the private key is equal the server cert's modulus, then it matches
		fmt.Printf("Verifying:\t%s with %s\n", serverCert.sourceFilename, serverCert.privateKeyFilename)

		if len(serverCert.privateKeyFilename) > 0 {
			var serverCertModulus interface{}
			var privateKeyModulus interface{}
			serverCertModulus, err = reflections.GetField(serverCert.certificate.PublicKey, "N")
			if err != nil {
				break
			}
			privateKeyModulus, err = reflections.GetField(serverCert.privateKey, "N")
			if reflect.DeepEqual(serverCertModulus, privateKeyModulus) {
				fmt.Print("Status: OK! ")
				if serverCert.privateKeyEncrypted {
					fmt.Print("- WARNING - The private key was encrypted and needs to be decrypted before use on PCF!")
				}
				fmt.Print("\n")
			} else {
				fmt.Print("Status: FAILED - The private key does not match the server cert\n")
			}
		} else {
			fmt.Print("Status: NOTCHECKED - The private key was not provided\n")
		}
	}

	return err
}

func (action *Action) binCertificates() ([]certToolCert, []certToolCert, []certToolCert, error) {

	var rootCACerts = []certToolCert{}
	var serverCerts = []certToolCert{}
	var err error

	for _, rootCAFilename := range action.data.RootCAFiles {
		var certBytes = []byte{}
		reader, err := action.fileIO.OpenReadOnly(rootCAFilename)

		if err != nil {
			return nil, nil, nil, err
		}

		certBytes, err = ioutil.ReadAll(reader)

		if err != nil {
			return nil, nil, nil, err
		}

		decodedCertBytes, err := splitCertPEMBytes(certBytes)
		if err != nil {
			return nil, nil, nil, err
		}

		x509Certs, err := x509.ParseCertificates(decodedCertBytes)
		if err != nil {
			return nil, nil, nil, err
		}

		for _, x509Cert := range x509Certs {
			rootCACerts = append(rootCACerts,
				certToolCert{sourceFilename: rootCAFilename, certificate: x509Cert})
		}
	}

	for _, serverCertFileSet := range action.data.ServerCertFiles {
		var certBytes = []byte{}

		reader, err := action.fileIO.OpenReadOnly(serverCertFileSet.ServerCertFilename)

		if err != nil {
			return nil, nil, nil, err
		}

		certBytes, err = ioutil.ReadAll(reader)

		if err != nil {
			return nil, nil, nil, err
		}

		decodedCertBytes, err := splitCertPEMBytes(certBytes)
		if err != nil {
			return nil, nil, nil, err
		}

		x509Certs, err := x509.ParseCertificates(decodedCertBytes)
		if err != nil {
			return nil, nil, nil, err
		}

		// Decode the private key
		var privateKey interface{}
		var privateKeyIsEncrypted = false
		if len(serverCertFileSet.ServerCertPrivateKeyFilename) > 0 {
			var keyBytes = []byte{}
			reader, err = action.fileIO.OpenReadOnly(serverCertFileSet.ServerCertPrivateKeyFilename)

			if err != nil {
				return nil, nil, nil, err
			}

			keyBytes, err = ioutil.ReadAll(reader)

			if err != nil {
				return nil, nil, nil, err
			}

			// Assume that there is only 1 private key in the file
			privateKeyBlock, _ := pem.Decode(keyBytes)

			var decodedPrivateKeyBytes []byte
			if x509.IsEncryptedPEMBlock(privateKeyBlock) {
				decodedPrivateKeyBytes, err = x509.DecryptPEMBlock(privateKeyBlock, []byte(serverCertFileSet.ServerCertPrivateKeyPassphrase))
				if err != nil {
					return nil, nil, nil, err
				}
				privateKeyIsEncrypted = true
			} else {
				decodedPrivateKeyBytes = privateKeyBlock.Bytes
			}

			privateKey, err = x509.ParsePKCS8PrivateKey(decodedPrivateKeyBytes)
			if err != nil {
				return nil, nil, nil, err
			}

		}

		for _, x509Cert := range x509Certs {
			serverCerts = append(serverCerts,
				certToolCert{sourceFilename: serverCertFileSet.ServerCertFilename,
					certificate: x509Cert, privateKeyFilename: serverCertFileSet.ServerCertPrivateKeyFilename,
					privateKey: privateKey, privateKeyEncrypted: privateKeyIsEncrypted})
		}

	}

	var intermediateCerts = []certToolCert{}
	for _, intermediateFilename := range action.data.IntermediateCertFiles {
		var certBytes = []byte{}
		reader, err := action.fileIO.OpenReadOnly(intermediateFilename)
		if err != nil {
			return nil, nil, nil, err
		}

		certBytes, err = ioutil.ReadAll(reader)
		if err != nil {
			return nil, nil, nil, err
		}

		decodedCertBytes, err := splitCertPEMBytes(certBytes)
		if err != nil {
			return nil, nil, nil, err
		}

		x509Certs, err := x509.ParseCertificates(decodedCertBytes)
		if err != nil {
			return nil, nil, nil, err
		}

		for _, x509Cert := range x509Certs {
			intermediateCerts = append(intermediateCerts,
				certToolCert{sourceFilename: intermediateFilename, certificate: x509Cert})
		}
	}

	// Do a quick check on the intermediate certs to ensure they're all intermediate
	// We'll update out intermediate cert list but also add them into a cert pool to be used for the
	// verification process
	newIntermediateSet := intermediateCerts[:0] // Do a filtering without allocating new lists.
	for _, cert := range intermediateCerts {
		if isServerCert(cert.certificate) {
			serverCerts = append(serverCerts, cert)
		} else if isRootCert(cert.certificate) {
			rootCACerts = append(rootCACerts, cert)
		} else {
			// This is the new intermediate set
			newIntermediateSet = append(newIntermediateSet, cert)
		}
	}
	intermediateCerts = newIntermediateSet

	return rootCACerts, intermediateCerts, serverCerts, err
}

func (action *Action) executeDecryptAction() error {

	return nil
}

func (action *Action) executeInfoAction() error {

	return nil
}

func (action *Action) executeServeAction() error {

	return nil
}

func isServerCert(input *x509.Certificate) bool {
	return govalidator.IsURL(input.Subject.CommonName) || govalidator.IsIP(input.Subject.CommonName)
}

func isRootCert(input *x509.Certificate) bool {
	// A self signed cert is one
	// where the Issuer and Subject are identical.
	// A root cert has this property, plus potentially
	// some other tests that could be used to determine this fact.
	// For simplicity, we'll use this as the test here.
	// http://www.ietf.org/rfc/rfc5280.txt
	return reflect.DeepEqual(input.Issuer, input.Subject)
}

// splitCert takes in a concatenated set of PEM certs and splits them out
// as a byte array of cert PEM blocks that can be used with the crypto/x509 Library
func splitCertPEMBytes(concatenatedPEMCerts []byte) ([]byte, error) {
	var blocks = []byte{}
	var err error
	remainder := concatenatedPEMCerts
	for len(remainder) > 0 {
		var singlePEMCert *pem.Block
		singlePEMCert, remainder = pem.Decode(remainder)
		if singlePEMCert == nil {
			err = fmt.Errorf("PEM Bytes Split - Error: PEM not parsed")
			break
		}
		blocks = append(blocks, singlePEMCert.Bytes...)

	}
	return blocks, err
}

// splitCert takes in a concatenated set of PEM certs and splits them out
// as a x509.Certificate array of cert PEM blocks that can be used with the crypto/x509 Library
func splitCertPEMx509(concatenatedPEMCerts []byte) ([]*x509.Certificate, error) {
	var certs = []*x509.Certificate{}
	var err error
	remainder := concatenatedPEMCerts
	for len(remainder) > 0 {
		var singlePEMCert *pem.Block
		singlePEMCert, remainder = pem.Decode(remainder)
		if singlePEMCert == nil {
			err = fmt.Errorf("PEM Bytes Split - Error: PEM not parsed")
			break
		}
		c, _ := x509.ParseCertificate(singlePEMCert.Bytes)
		certs = append(certs, c)
	}
	return certs, err
}
