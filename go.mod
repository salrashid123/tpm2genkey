module github.com/salrashid123/tpm2genkey

go 1.22.0

toolchain go1.22.5

require (
	github.com/foxboron/go-tpm-keyfiles v0.0.0-20240620184055-b891af1cbc88
	github.com/google/go-tpm v0.9.2-0.20240625170440-991b038b62b6
	github.com/google/go-tpm-tools v0.4.4
	github.com/stretchr/testify v1.8.3
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/zenazn/pkcs7pad v0.0.0-20170308005700-253a5b1f0e03 // indirect
	golang.org/x/crypto v0.19.0 // indirect
	golang.org/x/sys v0.21.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

//replace github.com/foxboron/go-tpm-keyfiles => ./go-tpm-keyfiles
