package certToolArgs_test

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestCspArguments(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "certToolArgs Suite")
}
