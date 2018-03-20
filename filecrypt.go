package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"syscall"

	encrypt "github.com/DanyJoly/go-encrypt"
	"golang.org/x/crypto/ssh/terminal"
)

// Command line flags
var verbose = flag.Bool("v", false, "Verbose mode.")
var compress = flag.Bool("c", false, "Compress the content before encrypting it.")
var recursive = flag.Bool("r", false, "If pointing to a folder, encrypt the folder content recursively (file by file).")
var asSingleFile = flag.Bool("single", false, "If pointing to a folder, encrypt the folder content as a single encrypted file.")
var salt = flag.String("salt", "", "Specify a custom encryption password salt.")

// loggerProxy is just like a regular log.Logger but supports extra settings.
var logger *loggerProxy

func main() {

	inputFile, outputFile := extractFlags()

	logger = newLoggerProxy(os.Stdout, os.Args[0], log.Ltime, *verbose)
	logger.SetFlags(log.Ltime)

	stats, e := os.Stat(inputFile)
	if e != nil {
		logger.Fatal(e)
	}

	if stats.IsDir() && !*recursive && !*asSingleFile {
		logger.Fatal("Input pointing to a folder and encrypting is neither recursive or as a single encrypted file.")
	}

	// Generate the encrypter
	salt, e := getSalt()
	if e != nil {
		logger.Fatal(e)
	}

	password, e := getPassword()
	if e != nil {
		logger.Fatal(e)
	}

	// TODO: password shouldn't have to be cast.
	encrypter, e := encrypt.NewEncrypter(string(password), salt)
	if e != nil {
		logger.Fatal(e)
	}

	if stats.IsDir() {
		logger.Fatalln("TODO: Folder encryption not supported yet.")
	}

	e = encryptFile(inputFile, stats, outputFile, encrypter)
	if e != nil {
		logger.Fatal(e)
	}
}

func extractFlags() (inputFilename string, outputFilename string) {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "%s [OPTION]... [INPUT FILE]... [OUTPUT FILE]...\n", os.Args[0])
		fmt.Fprint(os.Stderr, "\nParameters:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if flag.NArg() < 2 {
		flag.Usage()
		os.Exit(-1)
	}

	return flag.Arg(0), flag.Arg(1)
}

func getSalt() ([]byte, error) {
	// Use user-specified salt
	if *salt != "" {
		return []byte(*salt), nil
	}

	return encrypt.GenerateSalt()
}

func getPassword() ([]byte, error) {
	fmt.Print("Enter Password: ")
	password, e := terminal.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	return password, e
}

func encryptFile(inputFile string, inputFileStats os.FileInfo, outputFile string, encrypter *encrypt.Encrypter) error {
	input, e := os.Open(inputFile)
	if e != nil {
		return e
	}
	defer func(input *os.File) {
		input.Close()
	}(input)

	buffer := make([]byte, inputFileStats.Size())
	n, e := input.Read(buffer)
	if e != nil {
		return e
	}

	if int64(n) != inputFileStats.Size() {
		// TODO: This should be based on a stream or support multiple calls to encrypt.
		return fmt.Errorf("unexpected file length change")
	}

	logger.Printf("Encrypting file '%s'...", inputFile)
	cyphertext, e := encrypter.Encrypt(buffer)
	if e != nil {
		return e
	}

	output, e := os.Create(outputFile)
	if e != nil {
		return e
	}
	defer func(output *os.File) {
		output.Close()
	}(output)

	_, e = output.Write(cyphertext)
	logger.Print("Done")

	return e
}
