package get_expiring

import (
	"time"

	hostdialer_mock "github.com/dawu415/PCFToolkit/cert/certificateRepository/hostdialer/mocks"

	ymlparser_mock "github.com/dawu415/PCFToolkit/cert/certificateRepository/ymlparser/mocks"

	"github.com/dawu415/PCFToolkit/cert/certificateRepository"
	"github.com/dawu415/PCFToolkit/cert/certificateRepository/certificate"
	certificate_mock "github.com/dawu415/PCFToolkit/cert/certificateRepository/certificate/mocks"
	fileIO_mock "github.com/dawu415/PCFToolkit/cert/certificateRepository/fileIO/mocks"
	privatekey_mock "github.com/dawu415/PCFToolkit/cert/certificateRepository/privatekey/mocks"
	"github.com/dawu415/PCFToolkit/cert/command/result"
	x509libmock "github.com/dawu415/PCFToolkit/cert/command/x509Lib/mocks"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Get-Expiring Command Test", func() {

	var getExpiringCommand *GetExpiring
	var mockx509Lib *x509libmock.X509LibMock
	var certRepo *certificateRepository.CertificateRepository
	var fileIOMock *fileIO_mock.MockFileIO
	var certLoader *certificate_mock.CertificateMock
	var keyLoader *privatekey_mock.PrivateKeyMock
	var ymlParser *ymlparser_mock.YMLParserDataMock
	var hostDialer *hostdialer_mock.HostDialerDataMock

	BeforeEach(func() {
		certRepo = certificateRepository.NewCertificateRepository()
		mockx509Lib = x509libmock.NewX509LibMock()

		fileIOMock = fileIO_mock.NewMockFileIO()
		certLoader = certificate_mock.NewPEMCertificateMock()
		keyLoader = privatekey_mock.NewPrivateKeyMock()
		ymlParser = ymlparser_mock.NewYMLParserDataMock()
		hostDialer = hostdialer_mock.NewHostDialerMock()
		certRepo = certificateRepository.NewCustomCertificateRepository(fileIOMock, certLoader, ymlParser, keyLoader, hostDialer)

		var options = Options{
			MinimumMonthsWarningToExpire: 6,
		}

		getExpiringCommand = NewGetExpiringCommandCustomGetExpiringLib(certRepo, &options, mockx509Lib)
	})

	It("should return a get_expiring command object", func() {
		var options = Options{
			MinimumMonthsWarningToExpire: 6,
		}
		getExpiringCmd := NewGetExpiringCommand(certRepo, &options)
		Expect(getExpiringCmd).ShouldNot(BeNil())
	})

	It("should be called the Get-Expiring command", func() {
		Expect(getExpiringCommand.Name()).Should(Equal("Get-Expiring"))
	})

	Context("There are no server certs", func() {
		It("should return nil", func() {

			getExpiringResult, ok := getExpiringCommand.Execute().Data().([]ResultData)

			Expect(ok).To(BeTrue())
			Expect(getExpiringResult).Should(BeNil())
		})
	})

	It("should return 2 items in list if there are 2 server certs", func() {
		fileIOMock.FileContent = "ABCD"
		fileIOMock.OpenAndReadFailed = false

		certLoader.CertificateType = certificate.TypeServerCertificate
		certLoader.LoadPEMCertificateFailed = false

		certRepo.InstallCertificates("somefile1.pem")
		certRepo.InstallCertificates("somefile2.pem")

		getExpiringResult, ok := getExpiringCommand.Execute().Data().([]ResultData)
		Expect(ok).To(BeTrue())

		Expect(getExpiringResult).Should(HaveLen(2))
	})

	It("should work with name filtering in Subject with 1 match", func() {
		fileIOMock.FileContent = "ABCD"
		fileIOMock.OpenAndReadFailed = false

		certLoader.CertificateType = certificate.TypeServerCertificate
		certLoader.LoadPEMCertificateFailed = false
		certLoader.SubjectCN = "Joe Blogs"

		certRepo.InstallCertificates("somefile1.pem")

		certLoader.CertificateType = certificate.TypeServerCertificate
		certLoader.LoadPEMCertificateFailed = false
		certLoader.SubjectCN = "DocDave"

		certRepo.InstallCertificates("somefile2.pem")

		getExpiringCommand.options.ContainsFilter = "Blogs"

		getExpiringResult, ok := getExpiringCommand.Execute().Data().([]ResultData)

		Expect(ok).To(BeTrue())

		Expect(getExpiringResult).Should(HaveLen(1))
		Expect(certRepo.ServerCerts).Should(HaveLen(2))
	})

	It("should work with name filtering in Subject with no match", func() {
		fileIOMock.FileContent = "ABCD"
		fileIOMock.OpenAndReadFailed = false

		certLoader.CertificateType = certificate.TypeServerCertificate
		certLoader.LoadPEMCertificateFailed = false
		certLoader.SubjectCN = "Joe Blogs"

		certRepo.InstallCertificates("somefile1.pem")

		certLoader.CertificateType = certificate.TypeServerCertificate
		certLoader.LoadPEMCertificateFailed = false
		certLoader.SubjectCN = "DocDave"

		certRepo.InstallCertificates("somefile2.pem")

		getExpiringCommand.options.ContainsFilter = "thisdoesntexist"

		getExpiringResult, ok := getExpiringCommand.Execute().Data().([]ResultData)

		Expect(ok).To(BeTrue())

		Expect(getExpiringResult).Should(HaveLen(0))
		Expect(certRepo.ServerCerts).Should(HaveLen(2))
	})

	Context("Test of Cert Expiry", func() {
		BeforeEach(func() {
			fileIOMock.FileContent = "ABCD"
			fileIOMock.OpenAndReadFailed = false

			certLoader.CertificateType = certificate.TypeServerCertificate
			certLoader.LoadPEMCertificateFailed = false
		})

		It("should fail if certificate is expired", func() {
			certLoader.NotBefore = time.Now().AddDate(0, -6, 0)
			certLoader.NotAfter = time.Now().AddDate(0, -2, 0) // Expired 2 months ago
			certRepo.InstallCertificates("somefile1.pem")

			getExpiringResult, ok := getExpiringCommand.Execute().Data().([]ResultData)

			Expect(ok).To(BeTrue())
			Expect(getExpiringResult).Should(HaveLen(1))
			Expect(getExpiringResult[0]).ShouldNot(BeNil())
			Expect(getExpiringResult).To(HaveLen(1))
			Expect(getExpiringResult[0].Status).Should(Equal(result.StatusFailed))
		})

		It("should fail if certificate is not valid yet", func() {
			certLoader.NotBefore = time.Now().AddDate(0, 5, 0) // Valid 5 months from now.
			certLoader.NotAfter = time.Now().AddDate(0, 10, 0)
			certRepo.InstallCertificates("somefile1.pem")

			getExpiringResult, ok := getExpiringCommand.Execute().Data().([]ResultData)

			Expect(ok).To(BeTrue())
			Expect(getExpiringResult).Should(HaveLen(1))
			Expect(getExpiringResult[0]).ShouldNot(BeNil())
			Expect(getExpiringResult[0].Status).Should(Equal(result.StatusFailed))
		})

		It("should warn if certificate has less than 6 months left", func() {
			certLoader.NotBefore = time.Now()
			certLoader.NotAfter = time.Now().AddDate(0, 6, 0)
			certRepo.InstallCertificates("somefile1.pem")

			getExpiringResult, ok := getExpiringCommand.Execute().Data().([]ResultData)

			Expect(ok).To(BeTrue())
			Expect(getExpiringResult).Should(HaveLen(1))
			Expect(getExpiringResult[0]).ShouldNot(BeNil())
			Expect(getExpiringResult[0].Status).Should(Equal(result.StatusWarning))
		})

		It("should succeed if certificate has more than 6 months left", func() {
			certLoader.NotBefore = time.Now()
			certLoader.NotAfter = time.Now().AddDate(0, 7, 0)
			certRepo.InstallCertificates("somefile1.pem")

			getExpiringResult, ok := getExpiringCommand.Execute().Data().([]ResultData)

			Expect(ok).To(BeTrue())
			Expect(getExpiringResult).Should(HaveLen(1))
			Expect(getExpiringResult[0]).ShouldNot(BeNil())
			Expect(getExpiringResult[0].Status).Should(Equal(result.StatusSuccess))

		})
	})
})
