package get_expiring

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestGetExpiringCommand(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Get Expiring Command Test")
}
