package certificateRepository

import (
	"github.com/dawu415/PCFToolkit/certtool/certificateRepository/certificate"
	"github.com/dawu415/PCFToolkit/certtool/certificateRepository/fileIO"
	"github.com/dawu415/PCFToolkit/certtool/certificateRepository/privatekey"
	"github.com/dawu415/PCFToolkit/certtool/certificateRepository/ymlparser"
)

// CertificateRepository defines a way to hold certificates and enable operations to be performed
// on these certificates
type CertificateRepository struct {
	RootCACerts       []certificate.Certificate
	IntermediateCerts []certificate.Certificate
	ServerCerts       []certificate.Certificate
	PrivateKeys       map[string]privatekey.PrivateKey
	fileIO            fileIO.FileIOInterface
	ymlParser         ymlparser.YMLParser
	certificateLoader certificate.PEMCertificateLoaderInterface
	privateKeyLoader  privatekey.PEMPrivateKeyLoaderInterface
}

// NewCustomCertificateRepository creates a new empty certificate repository with custom fileIO, certificateloader and privatekeyloader
func NewCustomCertificateRepository(
	fio fileIO.FileIOInterface,
	certLoader certificate.PEMCertificateLoaderInterface,
	ymlParser ymlparser.YMLParser,
	keyLoader privatekey.PEMPrivateKeyLoaderInterface) *CertificateRepository {

	return &CertificateRepository{
		RootCACerts:       []certificate.Certificate{},
		IntermediateCerts: []certificate.Certificate{},
		ServerCerts:       []certificate.Certificate{},
		PrivateKeys:       map[string]privatekey.PrivateKey{},
		fileIO:            fio,
		ymlParser:         ymlParser,
		certificateLoader: certLoader,
		privateKeyLoader:  keyLoader,
	}
}

// NewCertificateRepository creates a new empty certificate repository
func NewCertificateRepository() *CertificateRepository {
	return &CertificateRepository{
		RootCACerts:       []certificate.Certificate{},
		IntermediateCerts: []certificate.Certificate{},
		ServerCerts:       []certificate.Certificate{},
		PrivateKeys:       map[string]privatekey.PrivateKey{},
		fileIO:            fileIO.NewFileIO(),
		ymlParser:         ymlparser.NewYMLParser(),
		certificateLoader: certificate.NewPEMCertificate(),
		privateKeyLoader:  privatekey.NewPrivateKey(),
	}
}

// InstallCertificateWithPrivateKey inserts a certificate and optionally, its private key into the current certificate repo.
// A passphrase can be optionally provided to decrypt an encrypted private key.
// If a passphrase is provided but the private key is not encrypted, this method will return an error
// It is assumed that there will be only one private key in the privateKey filename specified by privateKeyFilename
func (repo *CertificateRepository) InstallCertificateWithPrivateKey(certFilename, privateKeyFilename, passphrase string) error {
	var err error
	err = repo.InstallCertificates(certFilename)
	if err == nil && len(privateKeyFilename) > 0 {
		err = repo.InstallPrivateKey(certFilename, privateKeyFilename, passphrase)
		// If we encountered an error, we should backtrack and remove the server certificates
		if err != nil {
			certsToKeep := repo.ServerCerts[:0] // Do a filtering without allocating new lists.
			for _, cert := range repo.ServerCerts {
				if cert.Label != certFilename {
					certsToKeep = append(certsToKeep, cert)
				}
			}
			repo.ServerCerts = certsToKeep
		}
	}

	return err
}

// InstallCertificatesFromYML inserts certificates into the current repo. from a yml field with a specific field
func (repo *CertificateRepository) InstallCertificatesFromYML(certYMLFilename, ymlPath string) error {
	var err error
	var YMLBytes []byte
	YMLBytes, err = repo.fileIO.OpenAndReadAll(certYMLFilename)

	if err == nil {
		var PEMCertBytes []byte
		var certificates []certificate.Certificate
		PEMCertBytes, err = repo.ymlParser.ParseContent(YMLBytes, ymlPath)
		if err == nil {
			certificates, err = repo.certificateLoader.LoadPEMCertificates(certYMLFilename+"--"+ymlPath, PEMCertBytes)
			if err == nil {
				for _, cert := range certificates {
					if cert.Type == certificate.TypeServerCertificate || cert.Type == certificate.TypeSelfSignedServerCertificate {
						repo.ServerCerts = append(repo.ServerCerts, cert)
					} else if cert.Type == certificate.TypeRootCACertificate {
						repo.RootCACerts = append(repo.RootCACerts, cert)
					} else {
						repo.IntermediateCerts = append(repo.IntermediateCerts, cert)
					}
				}
			}
		}
	}
	return err
}

// InstallCertificates inserts certificates into the current repo. The certificate file may contain multiple certificates
func (repo *CertificateRepository) InstallCertificates(certFilename string) error {
	var err error
	var PEMCertBytes []byte
	PEMCertBytes, err = repo.fileIO.OpenAndReadAll(certFilename)
	if err == nil {
		var certificates []certificate.Certificate
		certificates, err = repo.certificateLoader.LoadPEMCertificates(certFilename, PEMCertBytes)
		if err == nil {
			for _, cert := range certificates {
				if cert.Type == certificate.TypeServerCertificate || cert.Type == certificate.TypeSelfSignedServerCertificate {
					repo.ServerCerts = append(repo.ServerCerts, cert)
				} else if cert.Type == certificate.TypeRootCACertificate {
					repo.RootCACerts = append(repo.RootCACerts, cert)
				} else {
					repo.IntermediateCerts = append(repo.IntermediateCerts, cert)
				}
			}
		}

	}
	return err
}

// InstallPrivateKey installs a private key into the current certificate repo.
// A passphrase can be optionally provided to decrypt an encrypted private key.
// If a passphrase is provided but the private key is not encrypted, this method will return an error
// It is assumed that there will be only one private key in the privateKey filename specified by privateKeyFilename
func (repo *CertificateRepository) InstallPrivateKey(serverCertLabel, privateKeyFilename, passphrase string) error {
	var err error
	if len(privateKeyFilename) > 0 {
		var keyBytes []byte
		if keyBytes, err = repo.fileIO.OpenAndReadAll(privateKeyFilename); err == nil {
			var privateKey privatekey.PrivateKey

			if privateKey, err = repo.privateKeyLoader.
				LoadPEMPrivateKey(privateKeyFilename, serverCertLabel, keyBytes, passphrase); err == nil {
				repo.PrivateKeys[serverCertLabel] = privateKey
			}
		}

	}
	return err
}
