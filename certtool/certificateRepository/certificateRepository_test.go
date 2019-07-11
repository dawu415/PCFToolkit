package certificateRepository_test

import (
	"github.com/dawu415/PCFToolkit/certtool/certificateRepository"
	"github.com/dawu415/PCFToolkit/certtool/certificateRepository/certificate"
	certificate_mock "github.com/dawu415/PCFToolkit/certtool/certificateRepository/certificate/mocks"
	fileIO_mock "github.com/dawu415/PCFToolkit/certtool/certificateRepository/fileIO/mocks"
	privatekey_mock "github.com/dawu415/PCFToolkit/certtool/certificateRepository/privatekey/mocks"
	ymlParser_mock "github.com/dawu415/PCFToolkit/certtool/certificateRepository/ymlparser/mocks"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Certificate Repository tests", func() {
	var cert *certificateRepository.CertificateRepository
	var fileIOMock *fileIO_mock.MockFileIO
	var certLoader *certificate_mock.CertificateMock
	var keyLoader *privatekey_mock.PrivateKeyMock
	var ymlParser *ymlParser_mock.YMLParserDataMock

	BeforeEach(func() {

		fileIOMock = fileIO_mock.NewMockFileIO()
		certLoader = certificate_mock.NewPEMCertificateMock()
		keyLoader = privatekey_mock.NewPrivateKeyMock()
		ymlParser = ymlParser_mock.NewYMLParserDataMock()
		cert = certificateRepository.NewCustomCertificateRepository(fileIOMock, certLoader, ymlParser, keyLoader)
	})

	It("should be able to successfully install a certificate from a YML file", func() {

		fileIOMock.FileContent = "ABCD"
		fileIOMock.OpenAndReadFailed = false

		ymlParser.EncounteredAnError = false
		certLoader.CertificateType = certificate.TypeServerCertificate
		certLoader.LoadPEMCertificateFailed = false

		err := cert.InstallCertificatesFromYML("somefile.pem", "/some/path")

		Expect(err).To(BeNil())
		Expect(len(cert.ServerCerts)).To(Equal(1))
		Expect(cert.ServerCerts[0].Type).To(Equal(certificate.TypeServerCertificate))
		Expect(cert.ServerCerts[0].Label).To(Equal("somefile.pem--/some/path"))
		Expect(cert.ServerCerts[0].Certificate.Raw).To(Equal([]byte("ABCD/some/path")))
		Expect(len(cert.RootCACerts)).To(Equal(0))
		Expect(len(cert.IntermediateCerts)).To(Equal(0))

	})

	It("should be able to successfully handle a failure to install a certificate from a YML file", func() {

		fileIOMock.FileContent = "ABCD"
		fileIOMock.OpenAndReadFailed = false

		ymlParser.EncounteredAnError = true
		certLoader.CertificateType = certificate.TypeServerCertificate
		certLoader.LoadPEMCertificateFailed = false

		err := cert.InstallCertificatesFromYML("somefile.pem", "/some/path")

		Expect(err).ToNot(BeNil())
		Expect(len(cert.ServerCerts)).To(Equal(0))
		Expect(len(cert.RootCACerts)).To(Equal(0))
		Expect(len(cert.IntermediateCerts)).To(Equal(0))

	})

	It("should be able to successfully install a server certificate", func() {

		fileIOMock.FileContent = "ABCD"
		fileIOMock.OpenAndReadFailed = false

		certLoader.CertificateType = certificate.TypeServerCertificate
		certLoader.LoadPEMCertificateFailed = false

		err := cert.InstallCertificates("somefile.pem")

		Expect(err).To(BeNil())
		Expect(len(cert.ServerCerts)).To(Equal(1))
		Expect(cert.ServerCerts[0].Type).To(Equal(certificate.TypeServerCertificate))
		Expect(cert.ServerCerts[0].Label).To(Equal("somefile.pem"))
		Expect(cert.ServerCerts[0].Certificate.Raw).To(Equal([]byte("ABCD")))
		Expect(len(cert.RootCACerts)).To(Equal(0))
		Expect(len(cert.IntermediateCerts)).To(Equal(0))
	})

	It("should be able to successfully install a root certificate", func() {

		fileIOMock.FileContent = "ABCD"
		fileIOMock.OpenAndReadFailed = false

		certLoader.CertificateType = certificate.TypeRootCACertificate
		certLoader.LoadPEMCertificateFailed = false

		err := cert.InstallCertificates("somefile.pem")

		Expect(err).To(BeNil())
		Expect(len(cert.RootCACerts)).To(Equal(1))
		Expect(cert.RootCACerts[0].Type).To(Equal(certificate.TypeRootCACertificate))
		Expect(cert.RootCACerts[0].Label).To(Equal("somefile.pem"))
		Expect(cert.RootCACerts[0].Certificate.Raw).To(Equal([]byte("ABCD")))
		Expect(len(cert.ServerCerts)).To(Equal(0))
		Expect(len(cert.IntermediateCerts)).To(Equal(0))
	})

	It("should be able to successfully install an intermediate certificate", func() {

		fileIOMock.FileContent = "ABCD"
		fileIOMock.OpenAndReadFailed = false

		certLoader.CertificateType = certificate.TypeIntermediateCertificate
		certLoader.LoadPEMCertificateFailed = false

		err := cert.InstallCertificates("somefile.pem")

		Expect(err).To(BeNil())
		Expect(len(cert.IntermediateCerts)).To(Equal(1))
		Expect(cert.IntermediateCerts[0].Type).To(Equal(certificate.TypeIntermediateCertificate))
		Expect(cert.IntermediateCerts[0].Label).To(Equal("somefile.pem"))
		Expect(cert.IntermediateCerts[0].Certificate.Raw).To(Equal([]byte("ABCD")))
		Expect(len(cert.ServerCerts)).To(Equal(0))
		Expect(len(cert.RootCACerts)).To(Equal(0))
	})

	It("should fail if it cannot read the file", func() {

		fileIOMock.FileContent = "ABCD"
		fileIOMock.OpenAndReadFailed = true

		certLoader.CertificateType = certificate.TypeIntermediateCertificate
		certLoader.LoadPEMCertificateFailed = false

		err := cert.InstallCertificates("somefile.pem")

		Expect(err).ToNot(BeNil())
		Expect(len(cert.IntermediateCerts)).To(Equal(0))
	})

	It("should fail if it cannot load/parse the cert", func() {

		fileIOMock.FileContent = "ABCD"
		fileIOMock.OpenAndReadFailed = false

		certLoader.CertificateType = certificate.TypeIntermediateCertificate
		certLoader.LoadPEMCertificateFailed = true

		err := cert.InstallCertificates("somefile.pem")

		Expect(err).ToNot(BeNil())
		Expect(len(cert.IntermediateCerts)).To(Equal(0))
	})

	It("should be able to load a private key if there were no problems", func() {

		fileIOMock.FileContent = "ABCD"
		fileIOMock.OpenAndReadFailed = false

		keyLoader.LoadPEMPrivateKeyFailed = false

		err := cert.InstallPrivateKey("somecert.pem", "private.key", "abcd")

		Expect(err).To(BeNil())
		Expect(len(cert.PrivateKeys)).To(Equal(1))
		Expect(cert.PrivateKeys["somecert.pem"]).ToNot(BeNil())
		Expect(cert.PrivateKeys["somecert.pem"].Label).To(Equal("private.key"))
		Expect(cert.PrivateKeys["somecert.pem"].ServerCertLabel).To(Equal("somecert.pem"))
		Expect(cert.PrivateKeys["somecert.pem"].PrivateKey.([]byte)).To(Equal([]byte("ABCDabcd")))
	})

	It("should fail to load a private key if there were problems with reading the file", func() {

		fileIOMock.FileContent = "ABCD"
		fileIOMock.OpenAndReadFailed = true

		keyLoader.LoadPEMPrivateKeyFailed = false
		err := cert.InstallPrivateKey("somecert.pem", "private.key", "abcd")
		Expect(err).ToNot(BeNil())
		Expect(len(cert.PrivateKeys)).To(Equal(0))
	})

	It("should fail to load a private key if there were problems with parsing the cert", func() {

		fileIOMock.FileContent = "ABCD"
		fileIOMock.OpenAndReadFailed = false

		keyLoader.LoadPEMPrivateKeyFailed = true
		err := cert.InstallPrivateKey("somecert.pem", "private.key", "abcd")
		Expect(err).ToNot(BeNil())
		Expect(len(cert.PrivateKeys)).To(Equal(0))
	})

	It("should be able to load a private key and server cert if there were no problems", func() {

		fileIOMock.FileContent = "ABCD"
		fileIOMock.OpenAndReadFailed = false

		certLoader.CertificateType = certificate.TypeServerCertificate
		certLoader.LoadPEMCertificateFailed = false

		keyLoader.LoadPEMPrivateKeyFailed = false

		err := cert.InstallCertificateWithPrivateKey("somecert.pem", "private.key", "abcd")

		Expect(err).To(BeNil())
		Expect(len(cert.PrivateKeys)).To(Equal(1))
		Expect(cert.PrivateKeys["somecert.pem"]).ToNot(BeNil())
		Expect(cert.PrivateKeys["somecert.pem"].Label).To(Equal("private.key"))
		Expect(cert.PrivateKeys["somecert.pem"].ServerCertLabel).To(Equal("somecert.pem"))
		Expect(cert.PrivateKeys["somecert.pem"].PrivateKey.([]byte)).To(Equal([]byte("ABCDabcd")))
		Expect(len(cert.ServerCerts)).To(Equal(1))
		Expect(cert.ServerCerts[0].Type).To(Equal(certificate.TypeServerCertificate))
		Expect(cert.ServerCerts[0].Label).To(Equal("somecert.pem"))
		Expect(cert.ServerCerts[0].Certificate.Raw).To(Equal([]byte("ABCD")))
	})

	It("should fail to load a server cert and private key if there were problems with reading the file", func() {

		fileIOMock.FileContent = "ABCD"
		fileIOMock.OpenAndReadFailed = true

		certLoader.CertificateType = certificate.TypeServerCertificate
		certLoader.LoadPEMCertificateFailed = false

		keyLoader.LoadPEMPrivateKeyFailed = false
		err := cert.InstallCertificateWithPrivateKey("somecert.pem", "private.key", "abcd")
		Expect(err).ToNot(BeNil())
		Expect(len(cert.PrivateKeys)).To(Equal(0))
		Expect(len(cert.ServerCerts)).To(Equal(0))
	})

	It("should fail to load a server cert and private key if there were problems with parsing the cert", func() {

		fileIOMock.FileContent = "ABCD"
		fileIOMock.OpenAndReadFailed = false

		certLoader.CertificateType = certificate.TypeServerCertificate
		certLoader.LoadPEMCertificateFailed = true

		keyLoader.LoadPEMPrivateKeyFailed = false
		err := cert.InstallCertificateWithPrivateKey("somecert.pem", "private.key", "abcd")
		Expect(err).ToNot(BeNil())
		Expect(len(cert.PrivateKeys)).To(Equal(0))
		Expect(len(cert.ServerCerts)).To(Equal(0))
	})

	It("should fail to load a server cert and private key if there were problems with parsing the private key", func() {

		fileIOMock.FileContent = "ABCD"
		fileIOMock.OpenAndReadFailed = false

		certLoader.CertificateType = certificate.TypeServerCertificate
		certLoader.LoadPEMCertificateFailed = false

		keyLoader.LoadPEMPrivateKeyFailed = true
		err := cert.InstallCertificateWithPrivateKey("somecert.pem", "private.key", "abcd")
		Expect(err).ToNot(BeNil())
		Expect(len(cert.PrivateKeys)).To(Equal(0))
		Expect(len(cert.ServerCerts)).To(Equal(0))
	})
})
