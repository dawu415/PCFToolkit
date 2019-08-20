package fileIO_mock

import (
	"fmt"
)

// MockFileIO struct
type MockFileIO struct {
	FileContent       string
	OpenAndReadFailed bool
}

// NewMockFileIO initializes a new mock decoder
func NewMockFileIO() *MockFileIO {
	return &MockFileIO{}
}

// OpenAndReadAll returns the content of a given input file
func (fio *MockFileIO) OpenAndReadAll(filename string) ([]byte, error) {
	var err error
	if fio.OpenAndReadFailed {
		err = fmt.Errorf("OpenAndReadFailed Set to TRUE")
	}
	return []byte(fio.FileContent), err
}
