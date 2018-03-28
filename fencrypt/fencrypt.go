package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"syscall"

	encrypt "github.com/DanyJoly/go-encrypt"
	filecrypt "github.com/DanyJoly/go-filecrypt"
	"golang.org/x/crypto/ssh/terminal"
)

// Command line flags
var verbose = flag.Bool("v", false, "Verbose mode.")
var compress = flag.Bool("c", false, "Compress the content before encrypting it.")
var password = flag.String("password", "", "Specify the encryption password instead of prompting the std input (optional).")
var salt = flag.String("salt", "", "Specify a custom password salt (optional). The salt must be compatible with encrypt.GenerateSalt() format.")

var logger *filecrypt.LoggerProxy

func main() {

	plainFilepath, cipherFilepath := extractFlags()

	logger = filecrypt.NewLoggerProxy(os.Stdout, os.Args[0], log.Ltime, *verbose)
	logger.SetFlags(log.Ltime)

	stats, e := os.Stat(plainFilepath)
	if e != nil {
		logger.Fatal(e)
	}

	// Generate the encrypter
	salt, e := getSalt()
	if e != nil {
		logger.Fatal(e)
	}

	pwd, e := getPassword()
	if e != nil {
		logger.Fatal(e)
	}

	encrypter, e := encrypt.NewEncrypter(pwd, salt)
	if e != nil {
		logger.Fatal(e)
	}

	if stats.IsDir() {
		logger.Printf("Encrypting directory '%s'...", plainFilepath)

		e = filecrypt.EncryptDir(plainFilepath, cipherFilepath, encrypter, *compress)
		if e != nil {
			logger.Fatal(e)
		}
	} else {
		logger.Printf("Encrypting file '%s'...", plainFilepath)

		e = filecrypt.EncryptFile(plainFilepath, cipherFilepath, encrypter, *compress)
		if e != nil {
			logger.Fatal(e)
		}
	}

	logger.Print("Done")
}

func extractFlags() (inputFilename string, outputFilename string) {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "%s [OPTIONS]... [INPUT FILE]... [OUTPUT FILE]...\n", os.Args[0])
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
	if *password != "" {
		return []byte(*password), nil
	}

	fmt.Print("Enter Password: ")
	password, e := terminal.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	return []byte(password), e
}
