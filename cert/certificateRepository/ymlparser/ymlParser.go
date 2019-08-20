package ymlparser

import (
	"fmt"

	boshtpl "github.com/cloudfoundry/bosh-cli/director/template"
	"github.com/cppforlife/go-patch/patch"
)

// YMLParser defines the interface to parse a yml file at a specific field pointing to certificates
type YMLParser interface {
	ParseContent(ymlBytes []byte, ymlPath string) ([]byte, error)
}

// YMLParserData holds the data for YMLParser
type YMLParserData struct {
}

// NewYMLParser instantiates an object for YMLParsing
func NewYMLParser() YMLParser {
	return &YMLParserData{}
}

// ParseContent will parse out the content out of a yml file at a specific path
func (yml *YMLParserData) ParseContent(ymlBytes []byte, ymlPath string) ([]byte, error) {

	tpl := boshtpl.NewTemplate(ymlBytes)
	staticVars := boshtpl.StaticVariables{}
	ops := patch.Ops{}

	evalOpts := boshtpl.EvaluateOpts{
		UnescapedMultiline: true,
		ExpectAllKeys:      false,
	}

	path, err := patch.NewPointerFromString(ymlPath)
	if err != nil {
		return nil, fmt.Errorf("cannot parse path: %s", err)
	}

	if path.IsSet() {
		evalOpts.PostVarSubstitutionOp = patch.FindOp{Path: path}
	}

	bytes, err := tpl.Evaluate(staticVars, ops, evalOpts)
	if err != nil {
		return nil, err
	}

	return bytes, nil
}
