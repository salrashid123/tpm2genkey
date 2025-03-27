package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"strconv"
	"strings"

	"net"
	"os"
	"slices"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/salrashid123/tpm2genkey"
)

const ()

var (
	help = flag.Bool("help", false, "print usage")

	mode = flag.String("mode", "", "create | tpm2pem | pem2tpm")

	// convert
	public  = flag.String("public", "", "[TPM2B_PUBLIC] public key. Requires --private")
	private = flag.String("private", "", "[TPM2B_PRIVATE] private key. Requires --public")

	// genkey
	alg = flag.String("alg", "rsa", "key algorithm: rsa, ecdsa, aes or hmac")

	pcrs               = flag.String("pcrs", "", "pcr banks to bind the key to")
	enablePolicySyntax = flag.Bool("enablePolicySyntax", false, "Enable policy syntax encoding")
	policyFile         = flag.String("policy", "", "policy to encode")
	authPolicyFile     = flag.String("authPolicy", "", "authPolicy to encode")

	// rsa
	exponent   = flag.Int("exponent", 65537, "RSA exponent")
	rsakeysize = flag.Int("rsakeysize", 2048, "RSA key size")

	// ecdsa
	curve = flag.String("curve", "prime256v1", "ECDSA curve one of [secp224r1|prime256v1|secp384r1|secp521r1]")

	// aes
	aesmode    = flag.String("aesmode", "cfb", "AES mode [cfb|crt|ofb|cbc|ecb]")
	aeskeysize = flag.Int("aeskeysize", 128, "AES keysize")

	// common
	tpmPath           = flag.String("tpm-path", "/dev/tpmrm0", "Create: Path to the TPM device (character device or a Unix socket).")
	password          = flag.String("password", "", "Password for the created key")
	ownerpw           = flag.String("ownerpw", "", "Owner Password for the created key")
	parentpw          = flag.String("parentpw", "", "Parent Password for the created key")
	parent            = flag.Uint("parent", uint(tpm2.TPMRHOwner.HandleValue()), "parent Handle (default  tpm2.TPMRHOwner: 0x40000001 // 1073741825)")
	description       = flag.String("description", "", "description for the PEM key File (optional)")
	in                = flag.String("in", "", "PEM Input File to convert")
	out               = flag.String("out", "", "PEM output File")
	version           = flag.Bool("version", false, "print version")
	Commit, Tag, Date string
)

var TPMDEVICES = []string{"/dev/tpm0", "/dev/tpmrm0"}

func openTPM(path string) (io.ReadWriteCloser, error) {
	if slices.Contains(TPMDEVICES, path) {
		return tpmutil.OpenTPM(path)
	} else if path == "simulator" {
		return simulator.Get() //GetWithFixedSeedInsecure(1073741825)
	} else {
		return net.Dial("tcp", path)
	}
}

func main() {
	flag.Parse()

	if *help {
		flag.PrintDefaults()
		return
	}

	if *version {
		// go build  -ldflags="-s -w -X main.Tag=$(git describe --tags --abbrev=0) -X main.Commit=$(git rev-parse HEAD)" cmd/main.go
		fmt.Printf("Version: %s\n", Tag)
		fmt.Printf("Date: %s\n", Date)
		fmt.Printf("Commit: %s\n", Commit)
		os.Exit(0)
	}

	if *mode == "tpm2pem" {
		fmt.Println("converting tpm2-->PEM")
		pu, err := os.ReadFile(*public)
		if err != nil {
			fmt.Printf("tpm2genkey: error reading public %v\n", err)
			os.Exit(1)
		}
		pr, err := os.ReadFile(*private)
		if err != nil {
			fmt.Printf("tpm2genkey: error reading private %v\n", err)
			os.Exit(1)
		}

		var policy []*keyfile.TPMPolicy
		var authPolicy []*keyfile.TPMAuthPolicy

		if *policyFile != "" {
			polBytes, err := os.ReadFile(*policyFile)
			if err != nil {
				fmt.Printf("tpm2genkey: error reading private %v\n", err)
				os.Exit(1)
			}

			var jpolicy tpm2genkey.PolicyJson
			err = json.Unmarshal(polBytes, &jpolicy)
			if err != nil {
				fmt.Printf("tpm2genkey: error unmarshalling Policy %v\n", err)
				os.Exit(1)
			}

			for _, p := range jpolicy.Policy {
				policy = append(policy, &keyfile.TPMPolicy{
					CommandCode:   p.CommandCode,
					CommandPolicy: p.CommandPolicy,
				})
			}
		}

		if *authPolicyFile != "" {
			authPolBytes, err := os.ReadFile(*authPolicyFile)
			if err != nil {
				fmt.Printf("tpm2genkey: error reading private %v\n", err)
				os.Exit(1)
			}

			var jauthpolicy tpm2genkey.AuthPolicyJson
			err = json.Unmarshal(authPolBytes, &jauthpolicy)
			if err != nil {
				fmt.Printf("tpm2genkey: error unmarshalling authPolicy %v\n", err)
				os.Exit(1)
			}

			for _, p := range jauthpolicy.AuthPolicy {
				n := p.Name
				var policy []*keyfile.TPMPolicy
				for _, r := range p.Policy {
					policy = append(policy, &keyfile.TPMPolicy{
						CommandCode:   r.CommandCode,
						CommandPolicy: r.CommandPolicy,
					})

				}

				authPolicy = append(authPolicy, &keyfile.TPMAuthPolicy{
					Name:   n,
					Policy: policy,
				})
			}
		}

		p, err := tpm2genkey.ToPEM(&tpm2genkey.ToPEMConfig{
			Public:      pu,
			Private:     pr,
			Parent:      uint32(*parent),
			Password:    []byte(*password),
			Description: *description,
			Policy:      policy,
			AuthPolicy:  authPolicy,
		})
		if err != nil {
			fmt.Printf("tpm2genkey: error converting = %v\n", err)
			os.Exit(1)
		}
		err = os.WriteFile(*out, p, 0644)
		if err != nil {
			fmt.Printf("tpm2genkey: failed to write private key to file %v\n", err)
			os.Exit(1)
		}
		return
	} else if *mode == "pem2tpm" {
		fmt.Println("converting PEM-->tpm2")
		ppem, err := os.ReadFile(*in)
		if err != nil {
			fmt.Printf("tpm2genkey: error reading public %v\n", err)
			os.Exit(1)
		}
		_, pu, pr, err := tpm2genkey.FromPEM(&tpm2genkey.FromPEMConfig{
			PEM: ppem,
		})
		if err != nil {
			fmt.Printf("tpm2genkey: error converting = %v\n", err)
			os.Exit(1)
		}
		err = os.WriteFile(*public, pu, 0644)
		if err != nil {
			fmt.Printf("tpm2genkey: failed to write public key to file %v\n", err)
			os.Exit(1)
		}
		err = os.WriteFile(*private, pr, 0644)
		if err != nil {
			fmt.Printf("tpm2genkey: failed to write private key to file %v\n", err)
			os.Exit(1)
		}
		return
	} else if *mode == "create" {

		if *out == "" {
			fmt.Printf("tpm2genkey: error must specify --out= parameter when generating new key\n")
			os.Exit(1)
		}
		if *alg != "rsa" && *alg != "ecdsa" && *alg != "aes" && *alg != "hmac" {
			fmt.Printf("tpm2genkey: error key algorithm must be either rsa, ecdsa, hmac or aes\n")
			os.Exit(1)
		}

		rwc, err := openTPM(*tpmPath)
		if err != nil {
			fmt.Printf("can't open TPM %v\n", err)
			os.Exit(1)
		}
		defer func() {
			rwc.Close()
		}()

		var uintpcrs []uint

		if len(*pcrs) > 0 {
			uintpcrs = make([]uint, len(strings.Split(*pcrs, ",")))
			for idx, i := range strings.Split(*pcrs, ",") {
				if i != "" {
					j, err := strconv.Atoi(i)
					if err != nil {
						fmt.Printf("tpm2genkey: error converting pcr list  %v\n", err)
						os.Exit(1)
					}
					uintpcrs[idx] = uint(j)
				}
			}
		}

		k, err := tpm2genkey.NewKey(&tpm2genkey.NewKeyConfig{
			TPMDevice:          rwc,
			Alg:                *alg,
			Exponent:           *exponent,
			Ownerpw:            []byte(*ownerpw),
			Parentpw:           []byte(*parentpw),
			Parent:             uint32(*parent),
			Password:           []byte(*password),
			RSAKeySize:         *rsakeysize,
			Curve:              *curve,
			Mode:               *aesmode,
			PCRs:               uintpcrs,
			AESKeySize:         *aeskeysize,
			Description:        *description,
			EnablePolicySyntax: *enablePolicySyntax,
		})
		if err != nil {
			fmt.Printf("tpm2genkey: problem creating key, %v \n", err)
			os.Exit(1)
		}

		err = os.WriteFile(*out, k, 0644)
		if err != nil {
			fmt.Printf("tpm2genkey: failed to write private key to file %v\n", err)
			os.Exit(1)
		}
	} else {
		fmt.Println("Unknown mode: must be create|pem2tpm|tpm2pem")
	}
}
