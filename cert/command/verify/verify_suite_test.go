package verify_test

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestVerifyCommand(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Verify Command Test")
}
