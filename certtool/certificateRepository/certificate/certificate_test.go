package certificate_test

import (
	"github.com/dawu415/PCFToolkit/certtool/certificateRepository/certificate"
	"github.com/dawu415/PCFToolkit/certtool/certificateRepository/pemDecoder/mocks"
	"github.com/dawu415/PCFToolkit/certtool/certificateRepository/x509Parser/mocks"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Certificate tests", func() {
	var cert certificate.PEMCertificateLoaderInterface
	var pemDecoderMock *pemDecoder_mock.PEMDataMock
	var x509ParserMock *x509parser_mock.X509ParseDataMock
	BeforeEach(func() {
		pemDecoderMock = pemDecoder_mock.NewPEMDecoderMock()
		x509ParserMock = x509parser_mock.Newx509ParserMock()

		cert = certificate.NewCustomPEMCertificate(pemDecoderMock, x509ParserMock)
	})

	It("should be able to successfully load a single certificate", func() {
		pemDecoderMock.PEMDecodeFailed = false
		x509ParserMock.ParseCertificatesFailed = false
		c, err := cert.LoadPEMCertificates("servercert", []byte("PEM"))

		Expect(err).To(BeNil())
		Expect(c).ToNot(BeNil())

		Expect(len(c)).To(Equal(1))
		Expect(c[0].Label).To(Equal("servercert"))
		Expect(c[0].Certificate.Raw).To(Equal([]byte("PEM")))
	})

	It("should be able to successfully load a root cert", func() {
		pemDecoderMock.PEMDecodeFailed = false
		x509ParserMock.ParseCertificatesFailed = false
		x509ParserMock.CertificateType = certificate.TypeRootCACertificate

		c, err := cert.LoadPEMCertificates("servercert", []byte("PEM"))

		Expect(err).To(BeNil())
		Expect(c).ToNot(BeNil())

		Expect(len(c)).To(Equal(1))
		Expect(c[0].Label).To(Equal("servercert"))
		Expect(c[0].Certificate.Raw).To(Equal([]byte("PEM")))
		Expect(c[0].Type).To(Equal(certificate.TypeRootCACertificate))
		Expect(c[0].IsRootCert()).To(BeTrue())
	})

	It("should be able to successfully load a server cert", func() {
		pemDecoderMock.PEMDecodeFailed = false
		x509ParserMock.ParseCertificatesFailed = false
		x509ParserMock.CertificateType = certificate.TypeServerCertificate

		c, err := cert.LoadPEMCertificates("servercert", []byte("PEM"))

		Expect(err).To(BeNil())
		Expect(c).ToNot(BeNil())

		Expect(len(c)).To(Equal(1))
		Expect(c[0].Label).To(Equal("servercert"))
		Expect(c[0].Certificate.Raw).To(Equal([]byte("PEM")))
		Expect(c[0].Type).To(Equal(certificate.TypeServerCertificate))
	})

	It("should be able to successfully load an intermediate cert", func() {
		pemDecoderMock.PEMDecodeFailed = false
		x509ParserMock.ParseCertificatesFailed = false
		x509ParserMock.CertificateType = certificate.TypeIntermediateCertificate

		c, err := cert.LoadPEMCertificates("servercert", []byte("PEM"))

		Expect(err).To(BeNil())
		Expect(c).ToNot(BeNil())

		Expect(len(c)).To(Equal(1))
		Expect(c[0].Label).To(Equal("servercert"))
		Expect(c[0].Certificate.Raw).To(Equal([]byte("PEM")))
		Expect(c[0].Type).To(Equal(certificate.TypeIntermediateCertificate))
	})

	It("should fail when PEM cannot be decoded", func() {
		pemDecoderMock.PEMDecodeFailed = true
		x509ParserMock.ParseCertificatesFailed = false
		_, err := cert.LoadPEMCertificates("servercert", []byte("PEM"))

		Expect(err).ToNot(BeNil())
	})
	It("should fail when certificate cannot be parsed", func() {
		pemDecoderMock.PEMDecodeFailed = false
		x509ParserMock.ParseCertificatesFailed = true
		_, err := cert.LoadPEMCertificates("servercert", []byte("PEM"))

		Expect(err).ToNot(BeNil())
	})
})
