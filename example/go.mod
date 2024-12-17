module main

go 1.22.5

require (
	github.com/foxboron/go-tpm-keyfiles v0.0.0-20240805214234-f870d6f1ff68
	github.com/google/go-tpm v0.9.2-0.20240625170440-991b038b62b6
	github.com/google/go-tpm-tools v0.4.4
	github.com/salrashid123/tpm2genkey v0.0.0
)

require (
	golang.org/x/crypto v0.19.0 // indirect
	golang.org/x/sys v0.21.0 // indirect
)

replace github.com/salrashid123/tpm2genkey => ../
