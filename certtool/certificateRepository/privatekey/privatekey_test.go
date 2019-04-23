package privatekey_test

import (
	"github.com/dawu415/PCFToolkit/certtool/certificateRepository/pemDecoder/mocks"
	"github.com/dawu415/PCFToolkit/certtool/certificateRepository/privatekey"
	"github.com/dawu415/PCFToolkit/certtool/certificateRepository/x509Parser/mocks"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("PrivateKey tests", func() {
	var privateKey privatekey.PEMPrivateKeyLoaderInterface
	var pemDecoderMock *pemDecoder_mock.PEMDataMock
	var x509ParserMock *x509parser_mock.X509ParseDataMock
	BeforeEach(func() {
		pemDecoderMock = pemDecoder_mock.NewPEMDecoderMock()
		x509ParserMock = x509parser_mock.Newx509ParserMock()

		privateKey = privatekey.NewCustomPrivateKey(pemDecoderMock, x509ParserMock)
	})

	It("should be able to successfully load an unencrypted private key", func() {
		pemDecoderMock.PEMDecodeFailed = false
		pemDecoderMock.KeyIsEncrypted = false
		pemDecoderMock.KeyDecryptionFailed = false
		x509ParserMock.ParsePrivateKeyFailed = false
		pk, err := privateKey.LoadPEMPrivateKey("test", "servercert", []byte("PEM"), "")

		Expect(err).To(BeNil())
		Expect(pk).ToNot(BeNil())

		Expect(pk.Label).To(Equal("test"))
		Expect(pk.ServerCertLabel).To(Equal("servercert"))

		pkb, ok := pk.PrivateKey.([]byte)
		Expect(ok).To(BeTrue())
		Expect(pkb).To(Equal([]byte("PEM")))
	})

	It("should be able to successfully load an encrypted private key", func() {
		pemDecoderMock.PEMDecodeFailed = false
		pemDecoderMock.KeyIsEncrypted = true
		pemDecoderMock.KeyDecryptionFailed = false
		x509ParserMock.ParsePrivateKeyFailed = false
		pk, err := privateKey.LoadPEMPrivateKey("test", "servercert", []byte("PEM"), "somekey")

		Expect(err).To(BeNil())
		Expect(pk).ToNot(BeNil())

		Expect(pk.Label).To(Equal("test"))
		Expect(pk.ServerCertLabel).To(Equal("servercert"))

		pkb, ok := pk.PrivateKey.([]byte)
		Expect(ok).To(BeTrue())
		Expect(pkb).To(Equal([]byte("PEM_decrypted_with_somekey")))
	})

	It("should fail to load a private key that cannot be decoded", func() {
		pemDecoderMock.PEMDecodeFailed = true
		pemDecoderMock.KeyIsEncrypted = true
		pemDecoderMock.KeyDecryptionFailed = false
		x509ParserMock.ParsePrivateKeyFailed = false
		_, err := privateKey.LoadPEMPrivateKey("test", "servercert", []byte("PEM"), "somekey")

		Expect(err).ToNot(BeNil())
	})

	It("should fail to load a private key that cannot be decrypted", func() {
		pemDecoderMock.PEMDecodeFailed = false
		pemDecoderMock.KeyIsEncrypted = true
		pemDecoderMock.KeyDecryptionFailed = true
		x509ParserMock.ParsePrivateKeyFailed = false
		_, err := privateKey.LoadPEMPrivateKey("test", "servercert", []byte("PEM"), "somekey")

		Expect(err).ToNot(BeNil())
	})

	It("should fail to load an unencrypted private key that cannot be parsed", func() {
		pemDecoderMock.PEMDecodeFailed = false
		pemDecoderMock.KeyIsEncrypted = true
		pemDecoderMock.KeyDecryptionFailed = false
		x509ParserMock.ParsePrivateKeyFailed = true
		_, err := privateKey.LoadPEMPrivateKey("test", "servercert", []byte("PEM"), "somekey")

		Expect(err).ToNot(BeNil())
	})

	It("should fail to load an unencrypted private key that has a passphrase input", func() {
		pemDecoderMock.PEMDecodeFailed = false
		pemDecoderMock.KeyIsEncrypted = false
		pemDecoderMock.KeyDecryptionFailed = false
		x509ParserMock.ParsePrivateKeyFailed = false
		_, err := privateKey.LoadPEMPrivateKey("test", "servercert", []byte("PEM"), "somekey")

		Expect(err).ToNot(BeNil())
	})
})
