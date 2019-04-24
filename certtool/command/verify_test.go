package command_test

import (
	"crypto/rsa"
	"math/big"
	"strings"
	"time"

	"github.com/dawu415/PCFToolkit/certtool/certificateRepository"
	"github.com/dawu415/PCFToolkit/certtool/certificateRepository/certificate"
	"github.com/dawu415/PCFToolkit/certtool/certificateRepository/certificate/mocks"
	"github.com/dawu415/PCFToolkit/certtool/certificateRepository/fileIO/mocks"
	"github.com/dawu415/PCFToolkit/certtool/certificateRepository/privatekey/mocks"
	"github.com/dawu415/PCFToolkit/certtool/command"
	"github.com/dawu415/PCFToolkit/certtool/command/x509Lib/mocks"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func filterSourceVerifyResults(sourceResults [][]command.Result, sourceType int) []command.Result {
	var filteredSourceVerifyResults []command.Result
	for _, sourceResult := range sourceResults {
		for _, verifyResult := range sourceResult {

			if verifyResult.Source == sourceType {
				filteredSourceVerifyResults = append(filteredSourceVerifyResults, verifyResult)
			}
		}
	}
	return filteredSourceVerifyResults
}

var _ = Describe("Verify Command Test", func() {

	var verifyCommand *command.Verify
	var mockVerifyLib *x509libmock.X509LibMock
	var certRepo *certificateRepository.CertificateRepository
	var fileIOMock *fileIO_mock.MockFileIO
	var certLoader *certificate_mock.CertificateMock
	var keyLoader *privatekey_mock.PrivateKeyMock
	var systemDomain string
	var appDomain string
	BeforeEach(func() {
		certRepo = certificateRepository.NewCertificateRepository()
		mockVerifyLib = x509libmock.NewX509LibMock()

		fileIOMock = fileIO_mock.NewMockFileIO()
		certLoader = certificate_mock.NewPEMCertificateMock()
		keyLoader = privatekey_mock.NewPrivateKeyMock()
		certRepo = certificateRepository.NewCustomCertificateRepository(fileIOMock, certLoader, keyLoader)

		systemDomain = "sys."
		appDomain = "apps."
		verifyCommand = command.NewVerifyCommandCustomVerifyLib(certRepo, systemDomain, appDomain, mockVerifyLib)
	})

	It("should be called the verify command", func() {
		Expect(verifyCommand.Name()).Should(Equal("Verify"))
	})

	Context("There are no server certs", func() {
		It("should return nil", func() {
			Expect(verifyCommand.Execute()).Should(BeNil())
		})
	})

	It("should return 2 items in list if there are 2 server certs", func() {
		fileIOMock.FileContent = "ABCD"
		fileIOMock.OpenAndReadFailed = false

		certLoader.CertificateType = certificate.TypeServerCertificate
		certLoader.LoadPEMCertificateFailed = false

		certRepo.InstallCertificates("somefile1.pem")
		certRepo.InstallCertificates("somefile2.pem")

		Expect(verifyCommand.Execute()).Should(HaveLen(2))
	})

	Context("No RootCA was provided", func() {
		BeforeEach(func() {
			fileIOMock.FileContent = "ABCD"
			fileIOMock.OpenAndReadFailed = false

			certLoader.CertificateType = certificate.TypeServerCertificate
			certLoader.LoadPEMCertificateFailed = false

			certRepo.InstallCertificates("somefile1.pem")
		})
		It("should still run when TrustChain exists", func() {
			mockVerifyLib.TrustChainExist = true
			verifyResult := verifyCommand.Execute()

			Expect(certRepo.RootCACerts).Should(HaveLen(0))
			Expect(verifyResult).Should(HaveLen(1))
			Expect(verifyResult[0]).ShouldNot(BeNil())
			filteredResults := filterSourceVerifyResults(verifyResult, command.SourceVerifyTrustChain)
			Expect(filteredResults).ToNot(BeNil())

			for _, verifyResult := range filteredResults {
				for _, stepResult := range verifyResult.StepResults {
					Expect(stepResult.Status).To(Equal(command.StatusSuccess))
				}
			}
		})

		It("should still run when TrustChain does not exist", func() {
			mockVerifyLib.TrustChainExist = false
			verifyResult := verifyCommand.Execute()
			Expect(certRepo.RootCACerts).Should(HaveLen(0))

			Expect(verifyResult).Should(HaveLen(1))
			Expect(verifyResult[0]).ShouldNot(BeNil())
			filteredResults := filterSourceVerifyResults(verifyResult, command.SourceVerifyTrustChain)
			Expect(filteredResults).ToNot(BeNil())

			for _, verifyResult := range filteredResults {
				for _, stepResult := range verifyResult.StepResults {
					Expect(stepResult.Status).To(Equal(command.StatusFailed))
				}
			}
		})
	})

	Context("RootCA was provided", func() {
		BeforeEach(func() {
			fileIOMock.FileContent = "ABCD"
			fileIOMock.OpenAndReadFailed = false

			certLoader.CertificateType = certificate.TypeServerCertificate
			certLoader.LoadPEMCertificateFailed = false

			certRepo.InstallCertificates("somefile1.pem")

			certLoader.CertificateType = certificate.TypeRootCACertificate
			certLoader.LoadPEMCertificateFailed = false

			certRepo.InstallCertificates("root.pem")
		})
		It("should still run when TrustChain exists", func() {
			mockVerifyLib.TrustChainExist = true
			verifyResult := verifyCommand.Execute()

			Expect(certRepo.RootCACerts).Should(HaveLen(1))
			Expect(verifyResult).Should(HaveLen(1))
			Expect(verifyResult[0]).ShouldNot(BeNil())
			filteredResults := filterSourceVerifyResults(verifyResult, command.SourceVerifyTrustChain)
			Expect(filteredResults).ToNot(BeNil())

			for _, verifyResult := range filteredResults {
				for _, stepResult := range verifyResult.StepResults {
					Expect(stepResult.Status).To(Equal(command.StatusSuccess))
				}
			}
		})

		It("should still run when TrustChain does not exist", func() {
			mockVerifyLib.TrustChainExist = false
			verifyResult := verifyCommand.Execute()
			Expect(certRepo.RootCACerts).Should(HaveLen(1))

			Expect(verifyResult).Should(HaveLen(1))
			Expect(verifyResult[0]).ShouldNot(BeNil())
			filteredResults := filterSourceVerifyResults(verifyResult, command.SourceVerifyTrustChain)
			Expect(filteredResults).ToNot(BeNil())

			for _, verifyResult := range filteredResults {
				for _, stepResult := range verifyResult.StepResults {
					Expect(stepResult.Status).To(Equal(command.StatusFailed))
				}
			}
		})
	})

	Context("Test of DNS names in Certificate", func() {
		var SANsInCert []string = []string{"*.apps.wu.com", "*.sys.wu.com", "*.login.sys.wu.com"}
		BeforeEach(func() {
			fileIOMock.FileContent = "ABCD"
			fileIOMock.OpenAndReadFailed = false

			certLoader.CertificateType = certificate.TypeServerCertificate
			certLoader.LoadPEMCertificateFailed = false
			certLoader.DNSNames = SANsInCert
			certRepo.InstallCertificates("somefile1.pem")
		})
		It("should run and provide tests for each subdomain types", func() {
			verifyResult := verifyCommand.Execute()

			Expect(verifyResult).Should(HaveLen(1))
			Expect(verifyResult[0]).ShouldNot(BeNil())
			filteredResults := filterSourceVerifyResults(verifyResult, command.SourceVerifyCertSANS)
			Expect(filteredResults).ToNot(BeNil())

			for _, verifyResult := range filteredResults {
				for _, stepResult := range verifyResult.StepResults {
					found := false
					for _, san := range SANsInCert {
						if strings.Contains(stepResult.Message, strings.Replace(san, ".wu.com", "", -1)) {
							found = true
							break
						}
					}
					if found {
						Expect(stepResult.Status).To(Equal(command.StatusSuccess))
					} else {
						Expect(stepResult.Status).To(Equal(command.StatusFailed))
					}
				}
			}
		})
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

			verifyResult := verifyCommand.Execute()

			Expect(verifyResult).Should(HaveLen(1))
			Expect(verifyResult[0]).ShouldNot(BeNil())
			filteredResults := filterSourceVerifyResults(verifyResult, command.SourceVerifyCertExpiry)
			Expect(filteredResults).To(HaveLen(1))

			Expect(filteredResults[0].StepResults[0].Status).To(Equal(command.StatusFailed))
		})

		It("should fail if certificate is not valid yet", func() {
			certLoader.NotBefore = time.Now().AddDate(0, 5, 0) // Valid 5 months from now.
			certLoader.NotAfter = time.Now().AddDate(0, 10, 0)
			certRepo.InstallCertificates("somefile1.pem")
			verifyResult := verifyCommand.Execute()

			Expect(verifyResult).Should(HaveLen(1))
			Expect(verifyResult[0]).ShouldNot(BeNil())
			filteredResults := filterSourceVerifyResults(verifyResult, command.SourceVerifyCertExpiry)
			Expect(filteredResults).To(HaveLen(1))

			Expect(filteredResults[0].StepResults[0].Status).To(Equal(command.StatusFailed))
		})

		It("should warn if certificate has less than 6 months left", func() {
			certLoader.NotBefore = time.Now()
			certLoader.NotAfter = time.Now().AddDate(0, 6, 0)
			certRepo.InstallCertificates("somefile1.pem")
			verifyResult := verifyCommand.Execute()

			Expect(verifyResult).Should(HaveLen(1))
			Expect(verifyResult[0]).ShouldNot(BeNil())
			filteredResults := filterSourceVerifyResults(verifyResult, command.SourceVerifyCertExpiry)
			Expect(filteredResults).To(HaveLen(1))

			Expect(filteredResults[0].StepResults[0].Status).To(Equal(command.StatusWarning))
		})

		It("should succeed if certificate has more than 6 months left", func() {
			certLoader.NotBefore = time.Now()
			certLoader.NotAfter = time.Now().AddDate(0, 7, 0)
			certRepo.InstallCertificates("somefile1.pem")
			verifyResult := verifyCommand.Execute()

			Expect(verifyResult).Should(HaveLen(1))
			Expect(verifyResult[0]).ShouldNot(BeNil())
			filteredResults := filterSourceVerifyResults(verifyResult, command.SourceVerifyCertExpiry)
			Expect(filteredResults).To(HaveLen(1))

			Expect(filteredResults[0].StepResults[0].Status).To(Equal(command.StatusSuccess))
		})
	})

	Context("Testing of Private Key and Certificate Match", func() {
		BeforeEach(func() {
			fileIOMock.FileContent = "ABCD"
			fileIOMock.OpenAndReadFailed = false

			certLoader.CertificateType = certificate.TypeServerCertificate
			certLoader.LoadPEMCertificateFailed = false

		})

		It("should not check if private key was not provided", func() {
			certRepo.InstallCertificates("somefile1.pem")

			verifyResult := verifyCommand.Execute()

			Expect(certRepo.PrivateKeys).Should(HaveLen(0))
			Expect(verifyResult).Should(HaveLen(1))
			Expect(verifyResult[0]).ShouldNot(BeNil())
			filteredResults := filterSourceVerifyResults(verifyResult, command.SourceVerifyCertPrivateKeyMatch)
			Expect(filteredResults).To(HaveLen(1))

			Expect(filteredResults[0].StepResults[0].Status).To(Equal(command.StatusNotChecked))
		})

		It("should fail if public key has invalid interface", func() {

			// By default, the Certificate Mock has an empty PublicKey
			certRepo.InstallCertificateWithPrivateKey("serverCert.crt", "private.key", "")
			verifyResult := verifyCommand.Execute()

			Expect(certRepo.PrivateKeys).Should(HaveLen(1))
			Expect(verifyResult).Should(HaveLen(1))
			Expect(verifyResult[0]).ShouldNot(BeNil())
			filteredResults := filterSourceVerifyResults(verifyResult, command.SourceVerifyCertPrivateKeyMatch)
			Expect(filteredResults).To(HaveLen(1))

			Expect(filteredResults[0].Error).ToNot(BeNil())
			Expect(filteredResults[0].StepResults[0].Status).To(Equal(command.StatusFailed))
		})
		It("should fail if private key has invalid interface", func() {
			// By default, the private key of keyload is empty
			certLoader.PublicKey = rsa.PublicKey{}
			certRepo.InstallCertificateWithPrivateKey("serverCert.crt", "private.key", "")
			verifyResult := verifyCommand.Execute()

			Expect(certRepo.PrivateKeys).Should(HaveLen(1))
			Expect(verifyResult).Should(HaveLen(1))
			Expect(verifyResult[0]).ShouldNot(BeNil())
			filteredResults := filterSourceVerifyResults(verifyResult, command.SourceVerifyCertPrivateKeyMatch)
			Expect(filteredResults).To(HaveLen(1))

			Expect(filteredResults[0].Error).ToNot(BeNil())
			Expect(filteredResults[0].StepResults[0].Status).To(Equal(command.StatusFailed))
		})
		It("should be successful if private key and public key match", func() {
			var publicKeyModulus = big.Int{}
			publicKeyModulus.SetUint64(1024)
			keyLoader.PrivateKey = rsa.PrivateKey{PublicKey: rsa.PublicKey{N: &publicKeyModulus}}
			certLoader.PublicKey = rsa.PublicKey{N: &publicKeyModulus}
			certRepo.InstallCertificateWithPrivateKey("serverCert.crt", "private.key", "")
			verifyResult := verifyCommand.Execute()

			Expect(certRepo.PrivateKeys).Should(HaveLen(1))
			Expect(verifyResult).Should(HaveLen(1))
			Expect(verifyResult[0]).ShouldNot(BeNil())
			filteredResults := filterSourceVerifyResults(verifyResult, command.SourceVerifyCertPrivateKeyMatch)
			Expect(filteredResults).To(HaveLen(1))

			Expect(filteredResults[0].Error).To(BeNil())
			Expect(filteredResults[0].StepResults[0].Status).To(Equal(command.StatusSuccess))
		})
		It("should be fail if private key and public key don't match", func() {
			var publicKeyModulus = big.Int{}
			var privateKeyModulus = big.Int{}
			publicKeyModulus.SetUint64(1024)
			privateKeyModulus.SetUint64(2048)
			keyLoader.PrivateKey = rsa.PrivateKey{PublicKey: rsa.PublicKey{N: &privateKeyModulus}}
			certLoader.PublicKey = rsa.PublicKey{N: &publicKeyModulus}
			certRepo.InstallCertificateWithPrivateKey("serverCert.crt", "private.key", "")
			verifyResult := verifyCommand.Execute()

			Expect(certRepo.PrivateKeys).Should(HaveLen(1))
			Expect(verifyResult).Should(HaveLen(1))
			Expect(verifyResult[0]).ShouldNot(BeNil())
			filteredResults := filterSourceVerifyResults(verifyResult, command.SourceVerifyCertPrivateKeyMatch)
			Expect(filteredResults).To(HaveLen(1))

			Expect(filteredResults[0].Error).To(BeNil())
			Expect(filteredResults[0].StepResults[0].Status).To(Equal(command.StatusFailed))
		})

	})
})
