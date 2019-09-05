package hostdialer_mock

import (
	"fmt"
)

// HostDialerDataMock holds the data for HostDialerMock
type HostDialerDataMock struct {
	HostIsInvalid bool
}

// NewHostDialerMock instantiates an object for YMLParsing
func NewHostDialerMock() *HostDialerDataMock {
	return &HostDialerDataMock{}
}

// GetPEMCertsFrom is a mocked function
func (h *HostDialerDataMock) GetPEMCertsFrom(host string, port int) ([]byte, error) {
	var err error
	var PEMCertBytes = []byte{}

	if h.HostIsInvalid {
		err = fmt.Errorf("HostIsInvalid was set to true")
	} else {
		PEMCertBytes = append(PEMCertBytes, []byte("abcd")...)
	}

	return PEMCertBytes, err
}
