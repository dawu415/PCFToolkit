package info

import (
	"github.com/dawu415/PCFToolkit/certtool/certificateRepository/certificate"
	"github.com/dawu415/PCFToolkit/certtool/command/result"
	"github.com/dawu415/PCFToolkit/certtool/command/x509Lib"

	"github.com/dawu415/PCFToolkit/certtool/certificateRepository"
)

// Info defines the struct holding the data necessary to execute an info command
type Info struct {
	certRepo                *certificateRepository.CertificateRepository
	x509Lib                 x509Lib.Interface
	filterRootCA            bool
	filterIntermediate      bool
	filterServerCertificate bool
	hidePEMOutput           bool
	containsFilter          string
}

// NewInfoCommand creates a new info command with a given certificate respository
func NewInfoCommand(certRepo *certificateRepository.CertificateRepository, filterRootCA, filterIntermediate, filterServerCertificate, hidePEMOutput bool, containsFilter string) *Info {
	// If no filtering option was selected, let's just make it all true, so that nothing is filtered out
	if filterRootCA == false &&
		filterIntermediate == false &&
		filterServerCertificate == false {
		filterRootCA = true
		filterIntermediate = true
		filterServerCertificate = true
	}
	return &Info{
		certRepo:                certRepo,
		x509Lib:                 x509Lib.NewX509Lib(),
		filterRootCA:            filterRootCA,
		filterIntermediate:      filterIntermediate,
		filterServerCertificate: filterServerCertificate,
		hidePEMOutput:           hidePEMOutput,
		containsFilter:          containsFilter,
	}
}

// NewInfoCommandCustomX509Lib returns a info command with given certificate repository and an x509Lib
func NewInfoCommandCustomX509Lib(certRepo *certificateRepository.CertificateRepository, filterRootCA, filterIntermediate, filterServerCertificate, hidePEMOutput bool, containsFilter string, x509Lib x509Lib.Interface) *Info {
	// If no filtering option was selected, let's just make it all true, so that nothing is filtered out
	if filterRootCA == false &&
		filterIntermediate == false &&
		filterServerCertificate == false {
		filterRootCA = true
		filterIntermediate = true
		filterServerCertificate = true
	}
	return &Info{
		certRepo:                certRepo,
		x509Lib:                 x509Lib,
		filterRootCA:            filterRootCA,
		filterIntermediate:      filterIntermediate,
		filterServerCertificate: filterServerCertificate,
		hidePEMOutput:           hidePEMOutput,
		containsFilter:          containsFilter,
	}
}

// Name describes the name of this command
func (cmd *Info) Name() string {
	return "Info"
}

// Execute performs the info command
func (cmd *Info) Execute() result.Result {
	var trustChainMap = map[certificate.Certificate]CertificateTrustChains{}

	for _, serverCert := range cmd.certRepo.ServerCerts {
		var trustChains, err = cmd.buildCertificateTrustChain(serverCert)

		trustChainMap[serverCert] = CertificateTrustChains{
			Chains: trustChains,
			Error:  err,
		}
	}
	for _, intCert := range cmd.certRepo.IntermediateCerts {
		var trustChains, err = cmd.buildCertificateTrustChain(intCert)

		trustChainMap[intCert] = CertificateTrustChains{
			Chains: trustChains,
			Error:  err,
		}
	}

	return &Result{
		certificates:            append(append(cmd.certRepo.ServerCerts, cmd.certRepo.IntermediateCerts...), cmd.certRepo.RootCACerts...),
		trustChains:             trustChainMap,
		filterRootCA:            cmd.filterRootCA,
		filterIntermediate:      cmd.filterIntermediate,
		filterServerCertificate: cmd.filterServerCertificate,
		hidePEMOutput:           cmd.hidePEMOutput,
		containsFilter:          cmd.containsFilter,
	}
}

func (cmd *Info) buildCertificateTrustChain(inputCert certificate.Certificate) ([][]certificate.Certificate, error) {
	var err error
	var chains [][]certificate.Certificate
	var chainCount = 0

	systemCerts, err := cmd.x509Lib.GetPartialSystemCertificates()

	if err == nil {
		allCerts := append(append(systemCerts, cmd.certRepo.IntermediateCerts...), cmd.certRepo.RootCACerts...)

		chains = make([][]certificate.Certificate, len(allCerts))

		// Do the initial level of certificate chains.
		// This may also include self-signed one level chain certs
		for _, cert := range allCerts {
			if cert.Certificate.Subject.CommonName == inputCert.Certificate.Issuer.CommonName {
				chains[chainCount] = append(chains[chainCount], inputCert)
				chains[chainCount] = append(chains[chainCount], cert)
				chainCount++
			}
		}

		// If we did not find any matching chains, we can shortcircuit this function and
		// initialize the first chain with just the input cert. This will allow
		// the output of an incomplete chain.
		if chainCount == 0 {
			chainCount = 1
			chains[0] = append(chains[0], inputCert)
			chains = chains[:chainCount]
		} else {
			// Resize the chains to the valid length of available certificates
			chains = chains[:chainCount]
			// Search for more intermediates given the initial search we performed above.
			if len(cmd.certRepo.IntermediateCerts) != 0 {
				for idx := range chains {
					for true {
						var currentCert = chains[idx][len(chains[idx])-1]

						if currentCert.IsRootCert() {
							break
						}

						for _, intCert := range cmd.certRepo.IntermediateCerts {
							if intCert.Certificate.Subject.CommonName == currentCert.Certificate.Issuer.CommonName {
								chains[idx] = append(chains[idx], intCert)
								break
							}
						}

						if currentCert == chains[idx][len(chains[idx])-1] {
							break
						}
					}
				}
			}

			// Search the root certs and determine the root chain
			if len(cmd.certRepo.RootCACerts) != 0 {
				for idx := range chains {
					for true {
						var currentCert = chains[idx][len(chains[idx])-1]

						if currentCert.IsRootCert() {
							break
						}

						for _, rootCert := range cmd.certRepo.RootCACerts {
							if rootCert.Certificate.Subject.CommonName == currentCert.Certificate.Issuer.CommonName {
								chains[idx] = append(chains[idx], rootCert)
								break
							}
						}
						if currentCert == chains[idx][len(chains[idx])-1] {
							break
						}
					}
				}
			}

			// Check if there are any chains that do not have a root cert. If so, it means our provided
			// root certs are not part of this server cert's trust chain.
			// We will search the system root certs instead.
			for idx := range chains {
				var lastCert = chains[idx][len(chains[idx])-1]
				if !lastCert.IsRootCert() {
					for _, sysCert := range systemCerts {
						if sysCert.Certificate.Subject.CommonName == lastCert.Certificate.Issuer.CommonName {
							chains[idx] = append(chains[idx], sysCert)
							break
						}
					}
				}
			}
		}
	}

	return chains, err
}
