package filecrypt

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/DanyJoly/go-encrypt"
)

var testEncryptOneFileFilepath, _ = filepath.Abs("./tests/inputs/onefile/input.txt")
var testEncryptMultiFilesDirepath, _ = filepath.Abs("./tests/inputs/multifiles")
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

	//cleanup()
}

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
