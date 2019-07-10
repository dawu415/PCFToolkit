package info_test

import (
	"crypto/x509"
	"crypto/x509/pkix"

	"github.com/dawu415/PCFToolkit/certtool/certificateRepository"
	"github.com/dawu415/PCFToolkit/certtool/certificateRepository/certificate"

	certificate_mock "github.com/dawu415/PCFToolkit/certtool/certificateRepository/certificate/mocks"
	fileIO_mock "github.com/dawu415/PCFToolkit/certtool/certificateRepository/fileIO/mocks"
	privatekey_mock "github.com/dawu415/PCFToolkit/certtool/certificateRepository/privatekey/mocks"
	"github.com/dawu415/PCFToolkit/certtool/command/info"
	x509libmock "github.com/dawu415/PCFToolkit/certtool/command/x509Lib/mocks"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Info Command Test", func() {

	var infoCommand *info.Info
	var mockx509Lib *x509libmock.X509LibMock
	var certRepo *certificateRepository.CertificateRepository
	var fileIOMock *fileIO_mock.MockFileIO
	var certLoader *certificate_mock.CertificateMock
	var keyLoader *privatekey_mock.PrivateKeyMock

	BeforeEach(func() {
		certRepo = certificateRepository.NewCertificateRepository()
		mockx509Lib = x509libmock.NewX509LibMock()

		fileIOMock = fileIO_mock.NewMockFileIO()
		certLoader = certificate_mock.NewPEMCertificateMock()
		keyLoader = privatekey_mock.NewPrivateKeyMock()
		certRepo = certificateRepository.NewCustomCertificateRepository(fileIOMock, certLoader, keyLoader)

		infoCommand = info.NewInfoCommandCustomX509Lib(certRepo, false, false, false, false, mockx509Lib)
	})

	It("should be called the info command", func() {
		Expect(infoCommand.Name()).Should(Equal("Info"))
	})

	Context("There are no server certs", func() {
		It("should return a set of certificates plus an empty trust chain map", func() {
			result := infoCommand.Execute()
			Expect(result).ShouldNot(BeNil())
			certInfo := result.Data().(info.CertificateInfo)
			Expect(certInfo.TrustChains).Should(BeEmpty())
			Expect(certInfo.Certificates).ShouldNot(BeNil())
		})
	})
	Context("There is a trust chain", func() {
		It("is using a provided root certificate", func() {

			// Load the Mock Server Cert
			certLoader.CertificateType = certificate.TypeServerCertificate
			certLoader.LoadPEMCertificateFailed = false
			certLoader.SubjectCN = "*.dawu.org"
			certLoader.IssuerCN = "dawu Enterprise Root CA"

			certRepo.InstallCertificates("MockServerCert.pem")

			// Load the Mock Root CA Cert
			certLoader.CertificateType = certificate.TypeRootCACertificate
			certLoader.LoadPEMCertificateFailed = false
			certLoader.SubjectCN = "dawu Enterprise Root CA"
			certLoader.IssuerCN = "dawu Enterprise Root CA"

			certRepo.InstallCertificates("MockRootCertdawuEnterprise.pem")

			// Load the Mock Root CA Cert (Of some other cert)
			certLoader.CertificateType = certificate.TypeRootCACertificate
			certLoader.LoadPEMCertificateFailed = false
			certLoader.SubjectCN = "dawu Investments Root CA"
			certLoader.IssuerCN = "dawu Investments Root CA"

			certRepo.InstallCertificates("MockRootCertdawuInvesments.pem")

			var result = infoCommand.Execute()
			certInfo, ok := result.Data().(info.CertificateInfo)

			Expect(ok).To(BeTrue())
			Expect(result).ShouldNot(BeNil())
			Expect(certInfo).ShouldNot(BeNil())
			Expect(len(certInfo.Certificates)).Should(Equal(3))

			var serverCert certificate.Certificate
			var rootCertEnterprise certificate.Certificate
			var rootCertInvestments certificate.Certificate

			for _, cert := range certInfo.Certificates {
				if cert.Label == "MockServerCert.pem" {
					serverCert = cert
				} else if cert.Label == "MockRootCertdawuEnterprise.pem" {
					rootCertEnterprise = cert
				} else {
					rootCertInvestments = cert
				}
			}

			Expect(serverCert).ToNot(BeNil())
			Expect(rootCertEnterprise).ToNot(BeNil())
			Expect(rootCertInvestments).ToNot(BeNil())

			Expect(certInfo.TrustChains[serverCert].Error).To(BeNil())
			Expect(len(certInfo.TrustChains[serverCert].Chains)).To(Equal(1))
			Expect(len(certInfo.TrustChains[serverCert].Chains[0])).To(Equal(2))
			Expect(certInfo.TrustChains[serverCert].Chains[0][0]).To(Equal(serverCert))
			Expect(certInfo.TrustChains[serverCert].Chains[0][1]).To(Equal(rootCertEnterprise))
		})

		It("is using a system root certificate", func() {
			// Load the Mock Server Cert
			certLoader.CertificateType = certificate.TypeServerCertificate
			certLoader.LoadPEMCertificateFailed = false
			certLoader.SubjectCN = "*.dawu.org"
			certLoader.IssuerCN = "DAWU ROOT X5"

			certRepo.InstallCertificates("MockServerCert.pem")

			// Add a mock system cert
			mockx509Lib.SystemCerts = append(mockx509Lib.SystemCerts,
				certificate.Certificate{
					Certificate: &x509.Certificate{
						Issuer: pkix.Name{CommonName: "DAWU ROOT X5"}, Subject: pkix.Name{CommonName: "DAWU ROOT X5"}},
				})

			var result = infoCommand.Execute()
			certInfo, ok := result.Data().(info.CertificateInfo)

			Expect(ok).To(BeTrue())
			Expect(result).ShouldNot(BeNil())
			Expect(certInfo).ShouldNot(BeNil())
			Expect(len(certInfo.Certificates)).Should(Equal(1))

			var serverCert = certInfo.Certificates[0]

			Expect(serverCert).ToNot(BeNil())
			Expect(certInfo.TrustChains[serverCert].Error).To(BeNil())
			Expect(len(certInfo.TrustChains[serverCert].Chains)).To(Equal(1))
			Expect(len(certInfo.TrustChains[serverCert].Chains[0])).To(Equal(2))
			Expect(certInfo.TrustChains[serverCert].Chains[0][0]).To(Equal(serverCert))
			Expect(certInfo.TrustChains[serverCert].Chains[0][1].IsRootCert()).To(BeTrue())
			Expect(certInfo.TrustChains[serverCert].Chains[0][1].Certificate.Issuer.CommonName).To(Equal("DAWU ROOT X5"))
		})

		It("Is missing an intermediate certificate", func() {

			// Load the Mock Server Cert
			certLoader.CertificateType = certificate.TypeServerCertificate
			certLoader.LoadPEMCertificateFailed = false
			certLoader.SubjectCN = "*.dawu.org"
			certLoader.IssuerCN = "dawu Enterprise X3 authority"

			certRepo.InstallCertificates("MockServerCert.pem")

			// Load the Mock Root CA Cert
			certLoader.CertificateType = certificate.TypeRootCACertificate
			certLoader.LoadPEMCertificateFailed = false
			certLoader.SubjectCN = "dawu Enterprise Root CA"
			certLoader.IssuerCN = "dawu Enterprise Root CA"

			certRepo.InstallCertificates("MockRootCACert.pem")

			var result = infoCommand.Execute()
			certInfo, ok := result.Data().(info.CertificateInfo)

			Expect(ok).To(BeTrue())
			Expect(result).ShouldNot(BeNil())
			Expect(certInfo).ShouldNot(BeNil())
			Expect(len(certInfo.Certificates)).Should(Equal(2))

			var serverCert certificate.Certificate
			if certInfo.Certificates[0].Label == "MockServerCert.pem" {
				serverCert = certInfo.Certificates[0]
			} else {
				serverCert = certInfo.Certificates[1]
			}

			Expect(certInfo.TrustChains[serverCert].Error).To(BeNil())
			Expect(len(certInfo.TrustChains[serverCert].Chains)).To(Equal(1))
			Expect(len(certInfo.TrustChains[serverCert].Chains[0])).To(Equal(1))
			Expect(certInfo.TrustChains[serverCert].Chains[0][0]).To(Equal(serverCert))
		})
	})
	Context("There is a no cert trust chain", func() {
		It("Is missing a root certificate", func() {

			// Load the Mock Server Cert
			certLoader.CertificateType = certificate.TypeServerCertificate
			certLoader.LoadPEMCertificateFailed = false
			certLoader.SubjectCN = "*.dawu.org"
			certLoader.IssuerCN = "dawu Enterprise X3 authority"

			certRepo.InstallCertificates("MockServerCert.pem")

			// Load the Mock Intermediate Cert
			certLoader.CertificateType = certificate.TypeIntermediateCertificate
			certLoader.LoadPEMCertificateFailed = false
			certLoader.SubjectCN = "dawu Enterprise X3 authority"
			certLoader.IssuerCN = "dawu Enterprise Root CA"

			certRepo.InstallCertificates("MockIntermediateCert.pem")

			var result = infoCommand.Execute()
			certInfo, ok := result.Data().(info.CertificateInfo)

			Expect(ok).To(BeTrue())
			Expect(result).ShouldNot(BeNil())
			Expect(certInfo).ShouldNot(BeNil())
			Expect(len(certInfo.Certificates)).Should(Equal(2))

			var serverCert certificate.Certificate
			var intCert certificate.Certificate
			if certInfo.Certificates[0].Label == "MockServerCert.pem" {
				serverCert = certInfo.Certificates[0]
				intCert = certInfo.Certificates[1]
			} else {
				serverCert = certInfo.Certificates[1]
				intCert = certInfo.Certificates[0]
			}

			Expect(certInfo.TrustChains[serverCert].Error).To(BeNil())
			Expect(len(certInfo.TrustChains[serverCert].Chains)).To(Equal(1))
			Expect(len(certInfo.TrustChains[serverCert].Chains[0])).To(Equal(2))
			Expect(certInfo.TrustChains[serverCert].Chains[0][0]).To(Equal(serverCert))
			Expect(certInfo.TrustChains[serverCert].Chains[0][1]).To(Equal(intCert))
		})

		It("Is missing an intermediate certificate", func() {

			// Load the Mock Server Cert
			certLoader.CertificateType = certificate.TypeServerCertificate
			certLoader.LoadPEMCertificateFailed = false
			certLoader.SubjectCN = "*.dawu.org"
			certLoader.IssuerCN = "dawu Enterprise X3 authority"

			certRepo.InstallCertificates("MockServerCert.pem")

			// Load the Mock Root CA Cert
			certLoader.CertificateType = certificate.TypeRootCACertificate
			certLoader.LoadPEMCertificateFailed = false
			certLoader.SubjectCN = "dawu Enterprise Root CA"
			certLoader.IssuerCN = "dawu Enterprise Root CA"

			certRepo.InstallCertificates("MockRootCACert.pem")

			var result = infoCommand.Execute()
			certInfo, ok := result.Data().(info.CertificateInfo)

			Expect(ok).To(BeTrue())
			Expect(result).ShouldNot(BeNil())
			Expect(certInfo).ShouldNot(BeNil())
			Expect(len(certInfo.Certificates)).Should(Equal(2))

			var serverCert certificate.Certificate
			if certInfo.Certificates[0].Label == "MockServerCert.pem" {
				serverCert = certInfo.Certificates[0]
			} else {
				serverCert = certInfo.Certificates[1]
			}

			Expect(certInfo.TrustChains[serverCert].Error).To(BeNil())
			Expect(len(certInfo.TrustChains[serverCert].Chains)).To(Equal(1))
			Expect(len(certInfo.TrustChains[serverCert].Chains[0])).To(Equal(1))
			Expect(certInfo.TrustChains[serverCert].Chains[0][0]).To(Equal(serverCert))
		})
	})

	Context("There are complex chains", func() {
		It("can handle a chains that have multiple intermediate certificates", func() {
			// Load the Mock Server Cert
			certLoader.CertificateType = certificate.TypeServerCertificate
			certLoader.LoadPEMCertificateFailed = false
			certLoader.SubjectCN = "*.dawu.org"
			certLoader.IssuerCN = "dawu Enterprise X3 authority"

			certRepo.InstallCertificates("MockServerCert.pem")

			// Load the Mock Intermediate Cert 1
			certLoader.CertificateType = certificate.TypeIntermediateCertificate
			certLoader.LoadPEMCertificateFailed = false
			certLoader.SubjectCN = "dawu Enterprise X3 authority"
			certLoader.IssuerCN = "dawu Special Dept X5 authority"

			certRepo.InstallCertificates("MockIntermediateEnterpriseX3Cert.pem")

			// Load the Mock Intermediate Cert 2
			certLoader.CertificateType = certificate.TypeIntermediateCertificate
			certLoader.LoadPEMCertificateFailed = false
			certLoader.SubjectCN = "dawu Special Dept X5 authority"
			certLoader.IssuerCN = "dawu Enterprise Root CA"

			certRepo.InstallCertificates("MockIntermediateSpecialDeptCert.pem")
			// Load the Mock Root CA Cert
			certLoader.CertificateType = certificate.TypeRootCACertificate
			certLoader.LoadPEMCertificateFailed = false
			certLoader.SubjectCN = "dawu Enterprise Root CA"
			certLoader.IssuerCN = "dawu Enterprise Root CA"

			certRepo.InstallCertificates("MockRootCACert.pem")

			var result = infoCommand.Execute()
			certInfo, ok := result.Data().(info.CertificateInfo)

			Expect(ok).To(BeTrue())
			Expect(result).ShouldNot(BeNil())
			Expect(certInfo).ShouldNot(BeNil())
			Expect(len(certInfo.Certificates)).Should(Equal(4))

			var serverCert certificate.Certificate
			var intCert1 certificate.Certificate
			var intCert2 certificate.Certificate
			var rootCert certificate.Certificate

			for _, cert := range certInfo.Certificates {
				if cert.Label == "MockServerCert.pem" {
					serverCert = cert
				} else if cert.Label == "MockIntermediateEnterpriseX3Cert.pem" {
					intCert1 = cert
				} else if cert.Label == "MockIntermediateSpecialDeptCert.pem" {
					intCert2 = cert
				} else {
					rootCert = cert
				}
			}
			Expect(serverCert).ToNot(BeNil())
			Expect(intCert1).ToNot(BeNil())
			Expect(intCert2).ToNot(BeNil())
			Expect(rootCert).ToNot(BeNil())

			Expect(certInfo.TrustChains[serverCert].Error).To(BeNil())
			Expect(len(certInfo.TrustChains[serverCert].Chains)).To(Equal(1))
			Expect(len(certInfo.TrustChains[serverCert].Chains[0])).To(Equal(4))
			Expect(certInfo.TrustChains[serverCert].Chains[0][0]).To(Equal(serverCert))
			Expect(certInfo.TrustChains[serverCert].Chains[0][1]).To(Equal(intCert1))
			Expect(certInfo.TrustChains[serverCert].Chains[0][2]).To(Equal(intCert2))
			Expect(certInfo.TrustChains[serverCert].Chains[0][3]).To(Equal(rootCert))
		})
		It("can handle a chains that have cross signed certificates", func() {
			// Load the Mock Server Cert
			certLoader.CertificateType = certificate.TypeServerCertificate
			certLoader.LoadPEMCertificateFailed = false
			certLoader.SubjectCN = "*.dawu.org"
			certLoader.IssuerCN = "dawu Enterprise X3 authority"

			certRepo.InstallCertificates("MockServerCert.pem")

			// Load the Mock Intermediate Cert 1
			certLoader.CertificateType = certificate.TypeIntermediateCertificate
			certLoader.LoadPEMCertificateFailed = false
			certLoader.SubjectCN = "dawu Enterprise X3 authority"
			certLoader.IssuerCN = "dawu Special Dept RootCA"

			certRepo.InstallCertificates("MockIntermediateSpecialDeptCert.pem")

			// Load the Mock Intermediate Cert 2
			certLoader.CertificateType = certificate.TypeIntermediateCertificate
			certLoader.LoadPEMCertificateFailed = false
			certLoader.SubjectCN = "dawu Enterprise X3 authority"
			certLoader.IssuerCN = "dawu Enterprise Root CA"

			certRepo.InstallCertificates("MockIntermediateEnterpriseCert.pem")

			// Load the Mock Root CA Cert
			certLoader.CertificateType = certificate.TypeRootCACertificate
			certLoader.LoadPEMCertificateFailed = false
			certLoader.SubjectCN = "dawu Enterprise Root CA"
			certLoader.IssuerCN = "dawu Enterprise Root CA"

			certRepo.InstallCertificates("MockRootCAEnterpriseCert.pem")

			// Load the Mock Root CA Cert
			certLoader.CertificateType = certificate.TypeRootCACertificate
			certLoader.LoadPEMCertificateFailed = false
			certLoader.SubjectCN = "dawu Special Dept RootCA"
			certLoader.IssuerCN = "dawu Special Dept RootCA"

			certRepo.InstallCertificates("MockRootCASpecialDeptCert.pem")

			var result = infoCommand.Execute()
			certInfo, ok := result.Data().(info.CertificateInfo)

			Expect(ok).To(BeTrue())
			Expect(result).ShouldNot(BeNil())
			Expect(certInfo).ShouldNot(BeNil())
			Expect(len(certInfo.Certificates)).Should(Equal(5))

			var serverCert certificate.Certificate
			var intCertSpecialDept certificate.Certificate
			var intCertEnterprise certificate.Certificate
			var rootCertSpecialDept certificate.Certificate
			var rootCertEnterprise certificate.Certificate

			for _, cert := range certInfo.Certificates {
				if cert.Label == "MockServerCert.pem" {
					serverCert = cert
				} else if cert.Label == "MockIntermediateSpecialDeptCert.pem" {
					intCertSpecialDept = cert
				} else if cert.Label == "MockIntermediateEnterpriseCert.pem" {
					intCertEnterprise = cert
				} else if cert.Label == "MockRootCAEnterpriseCert.pem" {
					rootCertEnterprise = cert
				} else {
					rootCertSpecialDept = cert
				}
			}
			Expect(serverCert).ToNot(BeNil())
			Expect(intCertSpecialDept).ToNot(BeNil())
			Expect(intCertEnterprise).ToNot(BeNil())
			Expect(rootCertSpecialDept).ToNot(BeNil())
			Expect(rootCertEnterprise).ToNot(BeNil())

			Expect(certInfo.TrustChains[serverCert].Error).To(BeNil())
			Expect(len(certInfo.TrustChains[serverCert].Chains)).To(Equal(2))

			Expect(len(certInfo.TrustChains[serverCert].Chains[0])).To(Equal(3))
			Expect(certInfo.TrustChains[serverCert].Chains[0][0]).To(Equal(serverCert))
			Expect(certInfo.TrustChains[serverCert].Chains[0][1]).To(Equal(intCertSpecialDept))
			Expect(certInfo.TrustChains[serverCert].Chains[0][2]).To(Equal(rootCertSpecialDept))

			Expect(len(certInfo.TrustChains[serverCert].Chains[1])).To(Equal(3))
			Expect(certInfo.TrustChains[serverCert].Chains[1][0]).To(Equal(serverCert))
			Expect(certInfo.TrustChains[serverCert].Chains[1][1]).To(Equal(intCertEnterprise))
			Expect(certInfo.TrustChains[serverCert].Chains[1][2]).To(Equal(rootCertEnterprise))

		})
	})
})
