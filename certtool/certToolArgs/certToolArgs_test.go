package certToolArgs_test

import (
	. "github.com/dawu415/PCFToolkit/certtool/certToolArgs"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("certToolArgs", func() {
	var ctaArgs *CertToolArguments
	BeforeEach(func() {
		ctaArgs = NewCertToolArguments()
	})

	It("Should fail to return a certToolArgs object if no arguments were supplied or if only the command argument was provided", func() {
		cta, err := ctaArgs.Process([]string{"certtool"})
		Expect(err).ShouldNot(HaveOccurred())
		Expect(cta).ToNot(BeNil())

		cta, err = ctaArgs.Process([]string{"certtool", "verify"})
		Expect(err).ShouldNot(HaveOccurred())
		Expect(cta).ToNot(BeNil())
	})

	It("Should fail if invalid command was provided", func() {
		cta, err := ctaArgs.Process([]string{"certtool", "somerandom_command_thing"})
		Expect(err).Should(HaveOccurred())
		Expect(cta).ToNot(BeNil())
	})

	It("Should not fail if valid command was provided", func() {
		cta, err := ctaArgs.Process([]string{"certtool", "verify"})
		Expect(err).ShouldNot(HaveOccurred())
		Expect(cta).ToNot(BeNil())

		cta, err = ctaArgs.Process([]string{"certtool", "info"})
		Expect(err).ShouldNot(HaveOccurred())
		Expect(cta).ToNot(BeNil())

		cta, err = ctaArgs.Process([]string{"certtool", "verify"})
		Expect(err).ShouldNot(HaveOccurred())
		Expect(cta).ToNot(BeNil())
	})

	It("should fail with invalid inputs to --server-cert ", func() {
		cta, err := ctaArgs.Process([]string{"certtool", "verify", "--server-cert"})
		Expect(err).Should(HaveOccurred())
		Expect(cta).ToNot(BeNil())

		cta, err = ctaArgs.Process([]string{"certtool", "verify", "--server-cert", "--TheNextCommand"})
		Expect(err).Should(HaveOccurred())
		Expect(cta).ToNot(BeNil())
	})

	It("should work with valid single server pem cert input to --server-cert ", func() {
		cta, err := ctaArgs.Process([]string{"certtool", "verify", "--server-cert", "server.pem"})
		Expect(err).ShouldNot(HaveOccurred())
		Expect(cta).ToNot(BeNil())
		Expect(len(cta.ServerCertFiles)).To(Equal(1))
		Expect(cta.ServerCertFiles[0].ServerCertFilename).To(Equal("server.pem"))
		Expect(cta.ServerCertFiles[0].ServerCertPrivateKeyFilename).To(Equal(""))
		Expect(cta.ServerCertFiles[0].ServerCertPrivateKeyPassphrase).To(Equal(""))
	})

	It("should work with valid single server pem cert + server key input to --server-cert ", func() {
		cta, err := ctaArgs.Process([]string{"certtool", "verify", "--server-cert", "server.pem", "server.key"})
		Expect(err).ShouldNot(HaveOccurred())
		Expect(cta).ToNot(BeNil())
		Expect(len(cta.ServerCertFiles)).To(Equal(1))
		Expect(cta.ServerCertFiles[0].ServerCertFilename).To(Equal("server.pem"))
		Expect(cta.ServerCertFiles[0].ServerCertPrivateKeyFilename).To(Equal("server.key"))
		Expect(cta.ServerCertFiles[0].ServerCertPrivateKeyPassphrase).To(Equal(""))
	})

	It("should work with valid single server pem cert + server key + passphrase input to --server-cert ", func() {
		cta, err := ctaArgs.Process([]string{"certtool", "verify", "--server-cert", "server.pem", "server.key", "abcd"})
		Expect(err).ShouldNot(HaveOccurred())
		Expect(cta).ToNot(BeNil())
		Expect(len(cta.ServerCertFiles)).To(Equal(1))
		Expect(cta.ServerCertFiles[0].ServerCertFilename).To(Equal("server.pem"))
		Expect(cta.ServerCertFiles[0].ServerCertPrivateKeyFilename).To(Equal("server.key"))
		Expect(cta.ServerCertFiles[0].ServerCertPrivateKeyPassphrase).To(Equal("abcd"))
	})

	It("should work with valid single server pem cert + server key + passphrase + some comma separated weird input to --server-cert ", func() {
		cta, err := ctaArgs.Process([]string{"certtool", "verify", "--server-cert", "server.pem", "server.key", "abcd", "justbecause"})
		Expect(err).ShouldNot(HaveOccurred())
		Expect(cta).ToNot(BeNil())
		Expect(len(cta.ServerCertFiles)).To(Equal(1))
		Expect(cta.ServerCertFiles[0].ServerCertFilename).To(Equal("server.pem"))
		Expect(cta.ServerCertFiles[0].ServerCertPrivateKeyFilename).To(Equal("server.key"))
		Expect(cta.ServerCertFiles[0].ServerCertPrivateKeyPassphrase).To(Equal("abcd"))
	})

	It("should work with valid multiple --server-cert ", func() {
		cta, err := ctaArgs.Process([]string{"certtool", "verify", "--server-cert", "server1.pem", "server1.key", "1234", "--server-cert", "server2.pem", "server2.key", "--server-cert", "server3.pem"})
		Expect(err).ShouldNot(HaveOccurred())
		Expect(cta).ToNot(BeNil())
		Expect(len(cta.ServerCertFiles)).To(Equal(3))
		Expect(cta.ServerCertFiles[0].ServerCertFilename).To(Equal("server1.pem"))
		Expect(cta.ServerCertFiles[0].ServerCertPrivateKeyFilename).To(Equal("server1.key"))
		Expect(cta.ServerCertFiles[0].ServerCertPrivateKeyPassphrase).To(Equal("1234"))
		Expect(cta.ServerCertFiles[1].ServerCertFilename).To(Equal("server2.pem"))
		Expect(cta.ServerCertFiles[1].ServerCertPrivateKeyFilename).To(Equal("server2.key"))
		Expect(cta.ServerCertFiles[1].ServerCertPrivateKeyPassphrase).To(Equal(""))
		Expect(cta.ServerCertFiles[2].ServerCertFilename).To(Equal("server3.pem"))
		Expect(cta.ServerCertFiles[2].ServerCertPrivateKeyFilename).To(Equal(""))
		Expect(cta.ServerCertFiles[2].ServerCertPrivateKeyPassphrase).To(Equal(""))
	})

	It("should work with valid single root ca using --root-ca ", func() {
		cta, err := ctaArgs.Process([]string{"certtool", "verify", "--root-ca", "root.pem"})
		Expect(err).ShouldNot(HaveOccurred())
		Expect(cta).ToNot(BeNil())
		Expect(len(cta.RootCAFiles)).To(Equal(1))
		Expect(cta.RootCAFiles[0]).To(Equal("root.pem"))
	})

	It("should fail when --root-ca has no arguments ", func() {
		_, err := ctaArgs.Process([]string{"certtool", "verify", "--root-ca"})
		Expect(err).Should(HaveOccurred())

		_, err = ctaArgs.Process([]string{"certtool", "verify", "--root-ca", "--cert", "cert.pem"})
		Expect(err).Should(HaveOccurred())
	})

	It("should work with valid multiple root ca using --root-ca ", func() {
		cta, err := ctaArgs.Process([]string{"certtool", "verify", "--root-ca", "root.pem", "--root-ca", "your-daddy.pem"})
		Expect(err).ShouldNot(HaveOccurred())
		Expect(cta).ToNot(BeNil())
		Expect(len(cta.RootCAFiles)).To(Equal(2))
		Expect(cta.RootCAFiles[0]).To(Equal("root.pem"))
		Expect(cta.RootCAFiles[1]).To(Equal("your-daddy.pem"))
	})

	It("should work with valid single cert using --cert ", func() {
		cta, err := ctaArgs.Process([]string{"certtool", "verify", "--cert", "cert.pem"})
		Expect(err).ShouldNot(HaveOccurred())
		Expect(cta).ToNot(BeNil())
		Expect(len(cta.IntermediateCertFiles)).To(Equal(1))
		Expect(cta.IntermediateCertFiles[0]).To(Equal("cert.pem"))
	})

	It("should fail when --cert has no input arguments", func() {
		_, err := ctaArgs.Process([]string{"certtool", "verify", "--cert"})
		Expect(err).Should(HaveOccurred())

		_, err = ctaArgs.Process([]string{"certtool", "verify", "--cert", "--root-ca", "root.pem"})
		Expect(err).Should(HaveOccurred())
	})

	It("should work with valid multiple cert using --cert ", func() {
		cta, err := ctaArgs.Process([]string{"certtool", "verify", "--cert", "cert1.pem", "--cert", "cert2.pem"})
		Expect(err).ShouldNot(HaveOccurred())
		Expect(cta).ToNot(BeNil())
		Expect(len(cta.IntermediateCertFiles)).To(Equal(2))
		Expect(cta.IntermediateCertFiles[0]).To(Equal("cert1.pem"))
		Expect(cta.IntermediateCertFiles[1]).To(Equal("cert2.pem"))
	})

	It("should work with a valid --apps-domain ", func() {
		cta, err := ctaArgs.Process([]string{"certtool", "verify", "--apps-domain", "appz"})
		Expect(err).ShouldNot(HaveOccurred())
		Expect(cta).ToNot(BeNil())
		Expect(cta.AppsDomain).To(Equal("appz"))
	})

	It("should failed with invalid input to --apps-domain ", func() {
		_, err := ctaArgs.Process([]string{"certtool", "verify", "--apps-domain"})
		Expect(err).Should(HaveOccurred())

		_, err = ctaArgs.Process([]string{"certtool", "verify", "--apps-domain", "--balh"})
		Expect(err).Should(HaveOccurred())
	})

	It("should failed if --apps-domain is not supported by a command", func() {
		_, err := ctaArgs.Process([]string{"certtool", "info", "--apps-domain", "apps"})
		Expect(err).Should(HaveOccurred())
	})

	It("should work with a valid --sys-domain ", func() {
		cta, err := ctaArgs.Process([]string{"certtool", "verify", "--sys-domain", "system"})
		Expect(err).ShouldNot(HaveOccurred())
		Expect(cta).ToNot(BeNil())
		Expect(cta.SystemDomain).To(Equal("system"))
	})

	It("should failed with invalid input to --sys-domain ", func() {
		_, err := ctaArgs.Process([]string{"certtool", "verify", "--sys-domain"})
		Expect(err).Should(HaveOccurred())

		_, err = ctaArgs.Process([]string{"certtool", "verify", "--sys-domain", "--balh"})
		Expect(err).Should(HaveOccurred())
	})

	It("should failed with invalid input to --sys-domain ", func() {
		_, err := ctaArgs.Process([]string{"certtool", "verify", "--sys-domain"})
		Expect(err).Should(HaveOccurred())

		_, err = ctaArgs.Process([]string{"certtool", "verify", "--sys-domain", "--balh"})
		Expect(err).Should(HaveOccurred())
	})

	It("should failed if --sys-domain is not supported by a command", func() {
		_, err := ctaArgs.Process([]string{"certtool", "info", "--sys-domain", "sys"})
		Expect(err).Should(HaveOccurred())
	})

	It("should fail if the verify command does not support a flag ", func() {
		_, err := ctaArgs.Process([]string{"certtool", "verify", "--private-key"})
		Expect(err).Should(HaveOccurred())
	})

	It("should fail if a command is not supported  ", func() {
		_, err := ctaArgs.Process([]string{"certtool", "blahblahbah", "--server-cert"})
		Expect(err).Should(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("Unknown command"))
	})

	It("should fail if an invalid flag is provided", func() {
		_, err := ctaArgs.Process([]string{"certtool", "verify", "--some-unsupported-thing"})
		Expect(err).Should(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("Unknown flag encountered"))
	})

	It("should be able to get help for a specific command", func() {
		cta, err := ctaArgs.Process([]string{"certtool", "verify", "--help"})
		Expect(err).ShouldNot(HaveOccurred())
		Expect(cta.PrintHelp).To(BeTrue())
	})

	It("should be able to get the usage string  ", func() {
		usageString := ctaArgs.GetUsage("")

		Expect(len(usageString)).ToNot(BeZero())
	})

	It("should be able to get the usage string for a specific command ", func() {
		usageStringNoCommand := ctaArgs.GetUsage("")

		usageStringWithCommand := ctaArgs.GetUsage("verify")

		Expect(len(usageStringNoCommand)).ToNot(BeZero())
		Expect(len(usageStringWithCommand)).ToNot(BeZero())
		Expect(len(usageStringWithCommand) > len(usageStringNoCommand)).Should(BeTrue())
	})
	It("should be able to get the usage string for a specific command even if it is invalid", func() {
		usageStringNoCommand := ctaArgs.GetUsage("")

		usageStringWithCommand := ctaArgs.GetUsage("booooooooo")

		Expect(len(usageStringNoCommand)).ToNot(BeZero())
		Expect(len(usageStringWithCommand)).ToNot(BeZero())
		Expect(len(usageStringWithCommand) == len(usageStringNoCommand)).Should(BeTrue())
	})
})
