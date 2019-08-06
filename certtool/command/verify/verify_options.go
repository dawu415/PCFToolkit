package verify

// Options hold the information for optional input flags for the Verify Commandå
type Options struct {
	SystemDomain                 string
	AppsDomain                   string
	VerifyTrustChain             bool
	VerifyDNS                    bool
	VerifyCertExpiration         bool
	VerifyCertPrivateKeyMatch    bool
	ContainsFilter               string
	MinimumMonthsWarningToExpire int
}
