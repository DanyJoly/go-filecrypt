/*
Simple command line tools to encrypt files or folders, and optionally compress them as well.

It acts similarly to a compression command line, where the output file is different from the input file.

It should work well for smaller files or folders (max 1GB) that can fit into system RAM.

Future improvements could be to create a stream encryption protocol to support encrypting file content as it's read
out of the file. Doing this, we'd loose the simplicity of the current encryption protocol, but it would allow for
any file size to be supported. Perhaps for a future version.

Usage example

	$ ls
	plaintext.txt

	$ fencrypt plaintext.txt encrypted
	Enter password:
	$ ls
	encrypted  plaintext.txt

	$ fdecrypt encrypted out/
	Enter password:
	$ ls -R
	.:
	encrypted  out/  plaintext.txt

	./out:
	plaintext.txt

Supported options

Usage of fencrypt:
	fencrypt [OPTIONS]... [INPUT FILE]... [OUTPUT FILE]...

	Parameters:
	-c    Compress the content before encrypting it.
	-password string
			Specify the encryption password instead of prompting the std input (optional).
	-salt string
			Specify a custom password salt (optional). The salt must be compatible with encrypt.GenerateSalt() format.
	-v    Verbose mode.

Usage of fdecrypt:
	fdecrypt [OPTIONS]... [INPUT FILE]... [OUTPUT FILE]...

	Parameters:
	-password string
			Specify the encryption password instead of prompting the std input (optional).
	-v    Verbose mode.
*/
package filecrypt
