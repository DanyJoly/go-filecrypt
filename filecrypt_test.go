package filecrypt

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/DanyJoly/go-encrypt"
)

var testEncryptOneFileFilepath, _ = filepath.Abs("./tests/inputs/onefile/input.txt")
var testEncryptManyFilesDirepath, _ = filepath.Abs("./tests/inputs/multifiles")
var testOutputDirpath, _ = filepath.Abs("./tests/output")
var testOutputDirpath2, _ = filepath.Abs("./tests/output2")

func TestEncryptOneFile(t *testing.T) {
	cleanup()

	encrypter, decrypter := createCrypto()
	filename := filepath.Base(testEncryptOneFileFilepath)
	cipherFilepath := filepath.Join(testOutputDirpath, filename)
	e := EncryptFile(testEncryptOneFileFilepath, cipherFilepath, encrypter)
	if e != nil {
		t.Errorf("Error encrypting file: %v", e)
	}

	plainFilepath := filepath.Join(testOutputDirpath2, filename)
	e = DecryptFile(cipherFilepath, plainFilepath, decrypter)
	if e != nil {
		t.Errorf("Error decrypting file: %v", e)
	}

	compareDirContent(filepath.Dir(testEncryptOneFileFilepath), testOutputDirpath2, t)

	cleanup()
}

//
// Helpers
//

func cleanup() {
	os.RemoveAll(testOutputDirpath)
	os.RemoveAll(testOutputDirpath2)
}

var salt encrypt.Salt // Reuse salt for tests perf

func createCrypto() (*encrypt.Encrypter, *encrypt.Decrypter) {
	if salt == nil {
		salt, _ = encrypt.GenerateSalt()
	}
	encrypter, _ := encrypt.NewEncrypter([]byte("hello"), salt)
	decrypter, _ := encrypt.NewDecrypter([]byte("hello"))

	return encrypter, decrypter
}

func compareDirContent(dirpath1, dirpath2 string, t *testing.T) {
	e := filepath.Walk(dirpath1, func(path string, info os.FileInfo, e error) error {
		if e != nil {
			return fmt.Errorf("Error comparing files in directories: %v", e)
		}

		if info.IsDir() {
			return nil
		}

		relpath, e := filepath.Rel(dirpath1, path)
		if e != nil {
			return fmt.Errorf("Error extracting relative filepath of %s: %v", path, e)
		}
		otherFilepath := filepath.Join(dirpath2, relpath)
		f1, e := os.Open(path)
		if e != nil {
			return fmt.Errorf("Error opening file %s: %v", path, e)
		}
		defer func(f1 *os.File) {
			f1.Close()
		}(f1)

		f2, e := os.Open(otherFilepath)
		if e != nil {
			return fmt.Errorf("Error opening file %s: %v", otherFilepath, e)
		}
		defer func(f2 *os.File) {
			f2.Close()
		}(f2)

		buffer1 := make([]byte, 1024*1024) // 1 MB
		buffer2 := make([]byte, 1024*1024) // 1 MB
		for e == nil {
			n1, e1 := f1.Read(buffer1)
			n2, e2 := f2.Read(buffer2)

			if e1 == io.EOF && e1 == e2 {
				return nil // Both at the EOF
			}

			if e1 != nil {
				return fmt.Errorf("Error reading file %s: %v", path, e)
			}

			if e2 != nil {
				return fmt.Errorf("Error reading file %s: %v", otherFilepath, e)
			}

			if n1 != n2 {
				return fmt.Errorf(
					"file '%s' and '%s' are expected to be identical, but they don't have the same length",
					path,
					otherFilepath)
			}

			if bytes.Compare(buffer1, buffer2) != 0 {
				return fmt.Errorf(
					"file '%s' and '%s' are expected to be identical, but their content is different",
					path,
					otherFilepath)
			}
		}

		return nil
	})
	if e != nil {
		t.Errorf("Error comparing directories: %v", e)
	}
}
