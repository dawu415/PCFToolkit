package fileIO

import (
	"io/ioutil"
	"os"
)

// FileIOInterface interface
type FileIOInterface interface {
	OpenAndReadAll(filename string) ([]byte, error)
}

// FileIO struct
type FileIO struct {
}

// NewFileIO creates a fileIO interface
func NewFileIO() FileIOInterface {
	return &FileIO{}
}

// OpenAndReadAll returns the content of a given input file
func (fio *FileIO) OpenAndReadAll(filename string) ([]byte, error) {
	var err error
	var bytes []byte
	if _, err = os.Stat(filename); !os.IsNotExist(err) {
		var fp *os.File
		if fp, err = os.Open(filename); err == nil {
			bytes, err = ioutil.ReadAll(fp)
		}
	}
	return bytes, err
}
