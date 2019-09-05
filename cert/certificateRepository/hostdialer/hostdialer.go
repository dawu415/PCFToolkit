package hostdialer

import (
	"crypto/tls"
	"encoding/pem"
	"fmt"
)

// HostDialer defines the interface to initiate connection to a host
type HostDialer interface {
	GetPEMCertsFrom(host string, port int) ([]byte, error)
}

// Data holds the data for HostDialer
type Data struct {
}

// NewHostDialer instantiates an object for Host Dialer
func NewHostDialer() HostDialer {
	return &Data{}
}

// GetPEMCertsFrom connects to a given host on a given port and returns an array of bytes pertaining to
// TLS certificates from the host in PEM format.
func (h *Data) GetPEMCertsFrom(host string, port int) ([]byte, error) {
	var err error
	var conn *tls.Conn
	var PEMCertBytes = []byte{}

	// We'll skip the TLS check, because we just want to get the certificate here.
	// If this is not done, this method may fail
	conn, err = tls.Dial("tcp", fmt.Sprintf("%s:%d", host, port), &tls.Config{InsecureSkipVerify: true})

	// If we can dial in without error, iterate through the peer certificates and convert them back into
	// PEM format to be returned.
	if err == nil {
		for _, cert := range conn.ConnectionState().PeerCertificates {
			PEMCertBytes = append(PEMCertBytes,
				pem.EncodeToMemory(&pem.Block{
					Type:  "CERTIFICATE",
					Bytes: cert.Raw,
				})...)
		}
	}
	return PEMCertBytes, err
}
