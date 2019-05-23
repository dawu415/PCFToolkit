package verify_test

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
	"github.com/dawu415/PCFToolkit/certtool/command/result"
	"github.com/dawu415/PCFToolkit/certtool/command/verify"
	"github.com/dawu415/PCFToolkit/certtool/command/x509Lib/mocks"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func filterSourceVerifyResults(sourceResults [][]verify.ResultData, sourceType int) []verify.ResultData {
	var filteredSourceVerifyResults []verify.ResultData
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

	var verifyCommand *verify.Verify
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

		systemDomain = "sys"
		appDomain = "apps"
		verifyCommand = verify.NewVerifyCommandCustomVerifyLib(certRepo, systemDomain, appDomain, mockVerifyLib)
	})

	It("should return a verify command object", func() {
		verifyCmd := verify.NewVerifyCommand(certRepo, "testsys", "testapp")
		Expect(verifyCmd).ShouldNot(BeNil())
	})

	It("should be called the verify command", func() {
		Expect(verifyCommand.Name()).Should(Equal("Verify"))
	})

	Context("There are no server certs", func() {
		It("should return nil", func() {
			verifyResult, ok := verifyCommand.Execute().Data().([][]verify.ResultData)

			Expect(ok).To(BeTrue())
			Expect(verifyResult).Should(BeNil())
		})
	})

	It("should return 2 items in list if there are 2 server certs", func() {
		fileIOMock.FileContent = "ABCD"
		fileIOMock.OpenAndReadFailed = false

		certLoader.CertificateType = certificate.TypeServerCertificate
		certLoader.LoadPEMCertificateFailed = false

		certRepo.InstallCertificates("somefile1.pem")
		certRepo.InstallCertificates("somefile2.pem")

		verifyResult, ok := verifyCommand.Execute().Data().([][]verify.ResultData)
		Expect(ok).To(BeTrue())

		Expect(verifyResult).Should(HaveLen(2))
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
			verifyResult, ok := verifyCommand.Execute().Data().([][]verify.ResultData)

			Expect(ok).To(BeTrue())
			Expect(certRepo.RootCACerts).Should(HaveLen(0))
			Expect(verifyResult).Should(HaveLen(1))
			Expect(verifyResult[0]).ShouldNot(BeNil())
			filteredResults := filterSourceVerifyResults(verifyResult, verify.SourceVerifyTrustChain)
			Expect(filteredResults).ToNot(BeNil())

			for _, verifyResult := range filteredResults {
				for _, stepResult := range verifyResult.StepResults {
					Expect(stepResult.Status).To(Equal(result.StatusSuccess))
				}
			}
		})

		It("should still run when TrustChain does not exist", func() {
			mockVerifyLib.TrustChainExist = false
			verifyResult, ok := verifyCommand.Execute().Data().([][]verify.ResultData)

			Expect(ok).To(BeTrue())
			Expect(certRepo.RootCACerts).Should(HaveLen(0))
			Expect(verifyResult).Should(HaveLen(1))
			Expect(verifyResult[0]).ShouldNot(BeNil())
			filteredResults := filterSourceVerifyResults(verifyResult, verify.SourceVerifyTrustChain)
			Expect(filteredResults).ToNot(BeNil())

			for _, verifyResult := range filteredResults {
				for _, stepResult := range verifyResult.StepResults {
					Expect(stepResult.Status).To(Equal(result.StatusFailed))
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
			verifyResult, ok := verifyCommand.Execute().Data().([][]verify.ResultData)

			Expect(ok).To(BeTrue())

			Expect(certRepo.RootCACerts).Should(HaveLen(1))
			Expect(verifyResult).Should(HaveLen(1))
			Expect(verifyResult[0]).ShouldNot(BeNil())
			filteredResults := filterSourceVerifyResults(verifyResult, verify.SourceVerifyTrustChain)
			Expect(filteredResults).ToNot(BeNil())

			for _, verifyResult := range filteredResults {
				for _, stepResult := range verifyResult.StepResults {
					Expect(stepResult.Status).To(Equal(result.StatusSuccess))
				}
			}
		})

		It("should still run when TrustChain does not exist", func() {
			mockVerifyLib.TrustChainExist = false
			verifyResult, ok := verifyCommand.Execute().Data().([][]verify.ResultData)

			Expect(ok).To(BeTrue())
			Expect(certRepo.RootCACerts).Should(HaveLen(1))

			Expect(verifyResult).Should(HaveLen(1))
			Expect(verifyResult[0]).ShouldNot(BeNil())
			filteredResults := filterSourceVerifyResults(verifyResult, verify.SourceVerifyTrustChain)
			Expect(filteredResults).ToNot(BeNil())

			for _, verifyResult := range filteredResults {
				for _, stepResult := range verifyResult.StepResults {
					Expect(stepResult.Status).To(Equal(result.StatusFailed))
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
			verifyResult, ok := verifyCommand.Execute().Data().([][]verify.ResultData)

			Expect(ok).To(BeTrue())

			Expect(verifyResult).Should(HaveLen(1))
			Expect(verifyResult[0]).ShouldNot(BeNil())
			filteredResults := filterSourceVerifyResults(verifyResult, verify.SourceVerifyCertSANS)
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
						Expect(stepResult.Status).To(Equal(result.StatusSuccess))
					} else {
						Expect(stepResult.Status).To(Equal(result.StatusFailed))
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

			verifyResult, ok := verifyCommand.Execute().Data().([][]verify.ResultData)

			Expect(ok).To(BeTrue())
			Expect(verifyResult).Should(HaveLen(1))
			Expect(verifyResult[0]).ShouldNot(BeNil())
			filteredResults := filterSourceVerifyResults(verifyResult, verify.SourceVerifyCertExpiry)
			Expect(filteredResults).To(HaveLen(1))

			Expect(filteredResults[0].StepResults[0].Status).To(Equal(result.StatusFailed))
		})

		It("should fail if certificate is not valid yet", func() {
			certLoader.NotBefore = time.Now().AddDate(0, 5, 0) // Valid 5 months from now.
			certLoader.NotAfter = time.Now().AddDate(0, 10, 0)
			certRepo.InstallCertificates("somefile1.pem")
			verifyResult, ok := verifyCommand.Execute().Data().([][]verify.ResultData)

			Expect(ok).To(BeTrue())
			Expect(verifyResult).Should(HaveLen(1))
			Expect(verifyResult[0]).ShouldNot(BeNil())
			filteredResults := filterSourceVerifyResults(verifyResult, verify.SourceVerifyCertExpiry)
			Expect(filteredResults).To(HaveLen(1))

			Expect(filteredResults[0].StepResults[0].Status).To(Equal(result.StatusFailed))
		})

		It("should warn if certificate has less than 6 months left", func() {
			certLoader.NotBefore = time.Now()
			certLoader.NotAfter = time.Now().AddDate(0, 6, 0)
			certRepo.InstallCertificates("somefile1.pem")
			verifyResult, ok := verifyCommand.Execute().Data().([][]verify.ResultData)

			Expect(ok).To(BeTrue())
			Expect(verifyResult).Should(HaveLen(1))
			Expect(verifyResult[0]).ShouldNot(BeNil())
			filteredResults := filterSourceVerifyResults(verifyResult, verify.SourceVerifyCertExpiry)
			Expect(filteredResults).To(HaveLen(1))

			Expect(filteredResults[0].StepResults[0].Status).To(Equal(result.StatusWarning))
		})

		It("should succeed if certificate has more than 6 months left", func() {
			certLoader.NotBefore = time.Now()
			certLoader.NotAfter = time.Now().AddDate(0, 7, 0)
			certRepo.InstallCertificates("somefile1.pem")
			verifyResult, ok := verifyCommand.Execute().Data().([][]verify.ResultData)

			Expect(ok).To(BeTrue())
			Expect(verifyResult).Should(HaveLen(1))
			Expect(verifyResult[0]).ShouldNot(BeNil())
			filteredResults := filterSourceVerifyResults(verifyResult, verify.SourceVerifyCertExpiry)
			Expect(filteredResults).To(HaveLen(1))

			Expect(filteredResults[0].StepResults[0].Status).To(Equal(result.StatusSuccess))
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

			verifyResult, ok := verifyCommand.Execute().Data().([][]verify.ResultData)

			Expect(ok).To(BeTrue())
			Expect(certRepo.PrivateKeys).Should(HaveLen(0))
			Expect(verifyResult).Should(HaveLen(1))
			Expect(verifyResult[0]).ShouldNot(BeNil())
			filteredResults := filterSourceVerifyResults(verifyResult, verify.SourceVerifyCertPrivateKeyMatch)
			Expect(filteredResults).To(HaveLen(1))

			Expect(filteredResults[0].StepResults[0].Status).To(Equal(result.StatusNotChecked))
		})

		It("should fail if public key has invalid interface", func() {

			// By default, the Certificate Mock has an empty PublicKey
			certRepo.InstallCertificateWithPrivateKey("serverCert.crt", "private.key", "")
			verifyResult, ok := verifyCommand.Execute().Data().([][]verify.ResultData)

			Expect(ok).To(BeTrue())
			Expect(certRepo.PrivateKeys).Should(HaveLen(1))
			Expect(verifyResult).Should(HaveLen(1))
			Expect(verifyResult[0]).ShouldNot(BeNil())
			filteredResults := filterSourceVerifyResults(verifyResult, verify.SourceVerifyCertPrivateKeyMatch)
			Expect(filteredResults).To(HaveLen(1))

			Expect(filteredResults[0].Error).ToNot(BeNil())
			Expect(filteredResults[0].StepResults[0].Status).To(Equal(result.StatusFailed))
		})
		It("should fail if private key has invalid interface", func() {
			// By default, the private key of keyload is empty
			certLoader.PublicKey = rsa.PublicKey{}
			certRepo.InstallCertificateWithPrivateKey("serverCert.crt", "private.key", "")
			verifyResult, ok := verifyCommand.Execute().Data().([][]verify.ResultData)

			Expect(ok).To(BeTrue())
			Expect(certRepo.PrivateKeys).Should(HaveLen(1))
			Expect(verifyResult).Should(HaveLen(1))
			Expect(verifyResult[0]).ShouldNot(BeNil())
			filteredResults := filterSourceVerifyResults(verifyResult, verify.SourceVerifyCertPrivateKeyMatch)
			Expect(filteredResults).To(HaveLen(1))

			Expect(filteredResults[0].Error).ToNot(BeNil())
			Expect(filteredResults[0].StepResults[0].Status).To(Equal(result.StatusFailed))
		})
		It("should be successful if private key and public key match", func() {
			var publicKeyModulus = big.Int{}
			publicKeyModulus.SetUint64(1024)
			keyLoader.PrivateKey = rsa.PrivateKey{PublicKey: rsa.PublicKey{N: &publicKeyModulus}}
			certLoader.PublicKey = rsa.PublicKey{N: &publicKeyModulus}
			certRepo.InstallCertificateWithPrivateKey("serverCert.crt", "private.key", "")
			verifyResult, ok := verifyCommand.Execute().Data().([][]verify.ResultData)

			Expect(ok).To(BeTrue())
			Expect(certRepo.PrivateKeys).Should(HaveLen(1))
			Expect(verifyResult).Should(HaveLen(1))
			Expect(verifyResult[0]).ShouldNot(BeNil())
			filteredResults := filterSourceVerifyResults(verifyResult, verify.SourceVerifyCertPrivateKeyMatch)
			Expect(filteredResults).To(HaveLen(1))

			Expect(filteredResults[0].Error).To(BeNil())
			Expect(filteredResults[0].StepResults[0].Status).To(Equal(result.StatusSuccess))
		})
		It("should be fail if private key and public key don't match", func() {
			var publicKeyModulus = big.Int{}
			var privateKeyModulus = big.Int{}
			publicKeyModulus.SetUint64(1024)
			privateKeyModulus.SetUint64(2048)
			keyLoader.PrivateKey = rsa.PrivateKey{PublicKey: rsa.PublicKey{N: &privateKeyModulus}}
			certLoader.PublicKey = rsa.PublicKey{N: &publicKeyModulus}
			certRepo.InstallCertificateWithPrivateKey("serverCert.crt", "private.key", "")
			verifyResult, ok := verifyCommand.Execute().Data().([][]verify.ResultData)

			Expect(ok).To(BeTrue())
			Expect(certRepo.PrivateKeys).Should(HaveLen(1))
			Expect(verifyResult).Should(HaveLen(1))
			Expect(verifyResult[0]).ShouldNot(BeNil())
			filteredResults := filterSourceVerifyResults(verifyResult, verify.SourceVerifyCertPrivateKeyMatch)
			Expect(filteredResults).To(HaveLen(1))

			Expect(filteredResults[0].Error).To(BeNil())
			Expect(filteredResults[0].StepResults[0].Status).To(Equal(result.StatusFailed))
		})

	})
})
