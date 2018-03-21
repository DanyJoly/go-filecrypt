package filecrypt

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	encrypt "github.com/DanyJoly/go-encrypt"
)

// EncryptFile will encrypt the file at plainFilepath and put the content in the file at cypherFilepath.
// If cypherFilepath already exists, it will overwrite its content. Otherwise it will create it and any subfolder
// required.
func EncryptFile(plainFilepath string, cypherFilepath string, encrypter *encrypt.Encrypter) error {

	plaintext, e := readAllFileContent(plainFilepath)
	if e != nil {
		return e
	}

	cyphertext, e := encrypter.Encrypt(plaintext)
	if e != nil {
		return e
	}

	return writeToFile(cypherFilepath, cyphertext)
}

// DecryptFile will decrypt the file at cypherFilepath and put the content in the file at plainFilepath.
// If plainFilepath already exists, it will overwrite its content. Otherwise it will create it and any subfolder
// required.
func DecryptFile(cypherFilepath string, plainFilepath string, decrypter *encrypt.Decrypter) error {

	cyphertext, e := readAllFileContent(cypherFilepath)
	if e != nil {
		return e
	}

	plaintext, e := decrypter.Decrypt(cyphertext)
	if e != nil {
		return e
	}

	return writeToFile(plainFilepath, plaintext)
}

func readAllFileContent(inputFilepath string) ([]byte, error) {
	fin, e := os.Open(inputFilepath)
	if e != nil {
		return nil, e
	}
	defer func(input *os.File) {
		input.Close()
	}(fin)

	inputFileStats, e := os.Stat(inputFilepath)
	if e != nil {
		return nil, e
	}

	buffer := make([]byte, inputFileStats.Size())
	n, e := fin.Read(buffer)
	if e != nil {
		return nil, e
	}

	// Opening a file in Go will not lock it from concurrent access (verified by test and by reading the Windows and
	// Linux implementation code as of Go V1.10). That's why we're a bit more careful to ensure that the file is not
	// being modified concurrently as the encrypted content could be corrupted.
	if n != len(buffer) {
		return nil, fmt.Errorf("file change detected during encryption (shorter than expected)")
	}

	extra := make([]byte, 1)
	n, e = fin.Read(extra)
	if n != 0 {
		return nil, fmt.Errorf("file change detected during encryption (larger than expected)")
	} else if e != io.EOF {
		return nil, fmt.Errorf("file change detected during encryption (unexpected error): %v", e)
	}

	return buffer, nil
}

func writeToFile(fpOut string, content []byte) error {
	// Create the directory if needed
	// Note: perm is ignored on windows as of Go V1.10
	e := os.MkdirAll(filepath.Dir(fpOut), 0600) // TODO: allow custom file permission
	if e != nil {
		return e
	}

	// Will truncate the file if it exists.
	fout, e := os.Create(fpOut)
	if e != nil {
		return e
	}
	defer func(output *os.File) {
		output.Close()
	}(fout)

	_, e = fout.Write(content)
	return e
}
