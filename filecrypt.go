package filecrypt

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"

	encrypt "github.com/DanyJoly/go-encrypt"
)

// initialZippedBufferSize controls the initial zipped content buffer size. This is a performance setting only.
// This utility currently store the intermediate zipped content to memory, not to a temp file. This is faster and
// cleaner for files that fit in memory, which is the expected usage for this tool.
const initialZippedBufferSize = 50 * 1024 * 1024 // 50MB

// EncryptFile will encrypt the file at plainFilepath and put the content in the file at cipherFilepath.
// If cipherFilepath already exists, it will overwrite its content. Otherwise it will create it and any subdirectory
// required.
func EncryptFile(plainFilepath string, cipherFilepath string, encrypter *encrypt.Encrypter, compress bool) error {

	files := [1]string{plainFilepath}
	return encryptContent(filepath.Dir(plainFilepath), files[:], cipherFilepath, encrypter, compress)
}

// EncryptDir will encrypt the whole directory at dirPath and put the content in the file at cipherFilepath.
// If cipherFilepath already exists, it will overwrite its content. Otherwise it will create it and any subdirectory
// required.
func EncryptDir(dirPath string, cipherFilepath string, encrypter *encrypt.Encrypter, compress bool) error {
	var files []string

	e := filepath.Walk(
		dirPath,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			// Skip over folders.
			if !info.IsDir() {
				files = append(files, path)
			}

			return nil
		})
	if e != nil {
		return e
	}

	return encryptContent(dirPath, files[:], cipherFilepath, encrypter, compress)
}

// DecryptFile will decrypt the file at cypherFilepath and put the content in the file at outputDir.
// If outputDir already exists, it will overwrite its content. Otherwise it will create it and any subdir
// required.
func DecryptFile(cypherFilepath string, outputDir string, decrypter *encrypt.Decrypter) error {

	cyphertext, e := readAllFileContent(cypherFilepath)
	if e != nil {
		return e
	}

	zippedtext, e := decrypter.Decrypt(cyphertext)
	if e != nil {
		return e
	}

	zipReader, e := zip.NewReader(bytes.NewReader(zippedtext), int64(len(zippedtext)))
	if e != nil {
		return e
	}

	for _, zf := range zipReader.File {
		e := unzipOneFile(outputDir, zf)
		if e != nil {
			return e
		}
	}

	return nil
}

func encryptContent(rootPath string, files []string, cipherFilepath string, encrypter *encrypt.Encrypter, compress bool) error {
	// This is where we will store the zipped output.
	// We set a buffer of length 0, but of a very large capacity to limit buffer copies.
	zipped := bytes.NewBuffer(make([]byte, 0, initialZippedBufferSize))

	// Regardless of if the user wants compression or not, we still use the zip format for simplicity.
	// This prevents branching the code and having to serialize to the file what we did for decompression.
	// We let the zip library handler that.
	e := zipContent(zipped, rootPath, files, compress)
	if e != nil {
		return e
	}

	fout, e := createFileAndTruncate(cipherFilepath)
	if e != nil {
		return e
	}
	defer func(output *os.File) {
		output.Close()
	}(fout)

	ciphertext, e := encrypter.Encrypt(zipped.Bytes())
	if e != nil {
		return e
	}

	return writeToFile(cipherFilepath, ciphertext)
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

// createFileAndTruncate will create the file at fp, truncating its content if it already exists.
func createFileAndTruncate(fp string) (*os.File, error) {
	// Create the directory if needed
	// Note: perm is ignored on windows as of Go V1.10
	dirPath := filepath.Dir(fp)
	e := os.MkdirAll(dirPath, os.ModePerm)
	if e != nil {
		return nil, fmt.Errorf("Error creating directory at '%s': %v", dirPath, e)
	}

	// Will truncate the file if it exists.
	return os.Create(fp)
}

func writeToFile(fpOut string, content []byte) error {

	fout, e := createFileAndTruncate(fpOut)
	if e != nil {
		return e
	}
	defer func(output *os.File) {
		output.Close()
	}(fout)

	_, e = fout.Write(content)
	return e
}

func zipContent(output io.Writer, rootPath string, files []string, compress bool) error {
	writer := zip.NewWriter(output)
	defer writer.Close()

	for _, file := range files {
		f, e := os.Open(file)
		if e != nil {
			return fmt.Errorf("error trying to open file '%s' for reading: %v", file, e)
		}
		defer f.Close()

		info, e := f.Stat()
		if e != nil {
			return fmt.Errorf("error extracting file info from file %s: %v", file, e)
		}

		header, e := zip.FileInfoHeader(info)
		if e != nil {
			return fmt.Errorf("error setting zip file header for file %s: %v", file, e)
		}
		// From the zip lib source code:
		// Because os.FileInfo's Name method returns only the base name of the file it describes, it may be necessary
		// to modify the Name field of the returned header to provide the full path name of the file.
		header.Name, e = filepath.Rel(rootPath, file)
		if e != nil {
			return fmt.Errorf("error extracting relative path from file %s: %v", file, e)
		}

		// Compression methods. Store won't compress at all.
		header.Method = zip.Store
		if compress {
			header.Method = zip.Deflate
		}

		w, e := writer.CreateHeader(header)
		if e != nil {
			return fmt.Errorf("error creating zip header for file %s: %v", file, e)
		}

		// Write the file into the zip writer for that file
		_, e = io.Copy(w, f)
		if e != nil {
			return fmt.Errorf("error zipping file %s: %v", file, e)
		}
	}

	return nil
}

// unzipOneFile is a helper to unzip one file from an archive
func unzipOneFile(outputDir string, zf *zip.File) error {
	zfReader, e := zf.Open()
	if e != nil {
		return fmt.Errorf("error opening compressed file '%s': %v", zf.Name, e)
	}
	defer zfReader.Close()

	outputFilepath := filepath.Join(outputDir, zf.Name)
	if zf.FileInfo().IsDir() {
		// It's a folder. Just create the folder.
		e := os.MkdirAll(outputFilepath, os.ModePerm)
		if e != nil {
			return fmt.Errorf("error creating directory at '%s': %v", outputFilepath, e)
		}
	} else {
		// Extract the file.
		fout, e := createFileAndTruncate(outputFilepath)
		if e != nil {
			return e
		}
		defer fout.Close()

		_, e = io.Copy(fout, zfReader)
		if e != nil {
			return fmt.Errorf("error uncompressing file '%s': %v", outputFilepath, e)
		}
	}

	return nil
}
