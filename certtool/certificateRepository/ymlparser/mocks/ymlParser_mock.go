package ymlparser_mock

import "fmt"

// YMLParserDataMock holds the data for the YMLParserDataMock
type YMLParserDataMock struct {
	EncounteredAnError bool
}

// NewYMLParserDataMock instantiates a mock object for the YMLParser interface
func NewYMLParserDataMock() *YMLParserDataMock {
	return &YMLParserDataMock{}
}

// ParseContent here is a mock parser for the YMLParser
func (yml *YMLParserDataMock) ParseContent(ymlBytes []byte, ymlPath string) ([]byte, error) {
	var err error
	if yml.EncounteredAnError {
		err = fmt.Errorf("EncounteredAnError was TRUE")
	}

	return append(ymlBytes, []byte(ymlPath)...), err
}
