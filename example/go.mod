module main

go 1.25.0

require (
	github.com/foxboron/go-tpm-keyfiles v0.0.0-20260427185012-515ba073c4c1
	github.com/google/go-tpm v0.9.9-0.20260124013517-8f8f42cba0de
	github.com/google/go-tpm-tools v0.4.8
	github.com/salrashid123/tpm2genkey v0.8.5
)

require (
	golang.org/x/crypto v0.52.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
)

replace github.com/salrashid123/tpm2genkey => ../
