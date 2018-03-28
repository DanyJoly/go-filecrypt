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
var password = flag.String("password", "", "Specify the encryption password instead of prompting the std input (optional).")

var logger *filecrypt.LoggerProxy

func main() {

	inputFile, outputFile := extractFlags()

	logger = filecrypt.NewLoggerProxy(os.Stdout, os.Args[0], log.Ltime, *verbose)
	logger.SetFlags(log.Ltime)

	stats, e := os.Stat(inputFile)
	if e != nil {
		logger.Fatal(e)
	}

	// Generate the decrypter
	pwd, e := getPassword()
	if e != nil {
		logger.Fatal(e)
	}

	decrypter, e := encrypt.NewDecrypter(pwd)
	if e != nil {
		logger.Fatal(e)
	}

	if stats.IsDir() {
		logger.Fatalln("Can't decrypt folders. Input must point to a file.")
	}

	logger.Printf("Decrypting file '%s'...", inputFile)

	e = filecrypt.DecryptFile(inputFile, outputFile, decrypter)
	if e != nil {
		logger.Fatal(e)
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

func getPassword() ([]byte, error) {
	if *password != "" {
		return []byte(*password), nil
	}

	fmt.Print("Enter Password: ")
	password, e := terminal.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	return password, e
}
