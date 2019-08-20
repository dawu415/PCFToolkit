package info

import (
	"testing"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestInfoCommand(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Info Command Test")
}
