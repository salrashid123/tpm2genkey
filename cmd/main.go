package main

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
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
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
	"github.com/salrashid123/tpm2genkey"
)

const ()

var (
	help = flag.Bool("help", false, "print usage")

	mode = flag.String("mode", "", "create | tpm2pem | pem2tpm | loadexternal")

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

	// loadexternal
	parentKeyType = flag.String("parentKeyType", "rsa_ek", "rsa_ek|ecc_ek|h2 (default rsa_ek)")

	// common
	tpmPath           = flag.String("tpm-path", "/dev/tpmrm0", "Create: Path to the TPM device (character device or a Unix socket).")
	password          = flag.String("password", "", "Password for the created key")
	ownerpw           = flag.String("ownerpw", "", "Owner Password for the created key")
	parentpw          = flag.String("parentpw", "", "Parent Password for the created key")
	parent            = flag.Uint("parent", uint(tpm2.TPMRHOwner.HandleValue()), "parent Handle (default  tpm2.TPMRHOwner: 0x40000001 // 1073741825)")
	description       = flag.String("description", "", "description for the PEM key File (optional)")
	in                = flag.String("in", "", "PEM Input File to load or convert")
	out               = flag.String("out", "", "PEM output File or context")
	persistentHandle  = flag.Int("persistentHandle", 0, "PersistentHandle to set the key to")
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
	os.Exit(run()) // since defer func() needs to get called first
}

func run() int {
	flag.Parse()

	if *help {
		flag.PrintDefaults()
		return 0
	}

	if *version {
		// go build  -ldflags="-s -w -X main.Tag=$(git describe --tags --abbrev=0) -X main.Commit=$(git rev-parse HEAD)" cmd/main.go
		fmt.Printf("Version: %s\n", Tag)
		fmt.Printf("Date: %s\n", Date)
		fmt.Printf("Commit: %s\n", Commit)
		return 0
	}

	switch *mode {
	case "tpm2pem":
		fmt.Println("converting tpm2-->PEM")
		pu, err := os.ReadFile(*public)
		if err != nil {
			fmt.Printf("tpm2genkey: error reading public %v\n", err)
			return 1
		}
		pr, err := os.ReadFile(*private)
		if err != nil {
			fmt.Printf("tpm2genkey: error reading private %v\n", err)
			return 1
		}

		var policy []*keyfile.TPMPolicy
		var authPolicy []*keyfile.TPMAuthPolicy

		if *policyFile != "" {
			polBytes, err := os.ReadFile(*policyFile)
			if err != nil {
				fmt.Printf("tpm2genkey: error reading private %v\n", err)
				return 1
			}

			var jpolicy tpm2genkey.PolicyJson
			err = json.Unmarshal(polBytes, &jpolicy)
			if err != nil {
				fmt.Printf("tpm2genkey: error unmarshalling Policy %v\n", err)
				return 1
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
				return 1
			}

			var jauthpolicy tpm2genkey.AuthPolicyJson
			err = json.Unmarshal(authPolBytes, &jauthpolicy)
			if err != nil {
				fmt.Printf("tpm2genkey: error unmarshalling authPolicy %v\n", err)
				return 1
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
			return 1
		}
		err = os.WriteFile(*out, p, 0644)
		if err != nil {
			fmt.Printf("tpm2genkey: failed to write private key to file %v\n", err)
			return 1
		}
	case "pem2tpm":
		fmt.Println("converting PEM-->tpm2")
		ppem, err := os.ReadFile(*in)
		if err != nil {
			fmt.Printf("tpm2genkey: error reading public %v\n", err)
			return 1
		}
		_, pu, pr, err := tpm2genkey.FromPEM(&tpm2genkey.FromPEMConfig{
			PEM: ppem,
		})
		if err != nil {
			fmt.Printf("tpm2genkey: error converting = %v\n", err)
			return 1
		}
		err = os.WriteFile(*public, pu, 0644)
		if err != nil {
			fmt.Printf("tpm2genkey: failed to write public key to file %v\n", err)
			return 1
		}
		err = os.WriteFile(*private, pr, 0644)
		if err != nil {
			fmt.Printf("tpm2genkey: failed to write private key to file %v\n", err)
			return 1
		}
	case "create":

		if *out == "" {
			fmt.Printf("tpm2genkey: error must specify --out= parameter when generating new key\n")
			return 1
		}
		if *alg != "rsa" && *alg != "ecdsa" && *alg != "aes" && *alg != "hmac" {
			fmt.Printf("tpm2genkey: error key algorithm must be either rsa, ecdsa, hmac or aes\n")
			return 1
		}

		rwc, err := openTPM(*tpmPath)
		if err != nil {
			fmt.Printf("can't open TPM %v\n", err)
			return 1
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
						return 1
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
			PersistentHandle:   *persistentHandle,
			EnablePolicySyntax: *enablePolicySyntax,
		})
		if err != nil {
			fmt.Printf("tpm2genkey: problem creating key, %v \n", err)
			return 1
		}

		err = os.WriteFile(*out, k, 0644)
		if err != nil {
			fmt.Printf("tpm2genkey: failed to write private key to file %v\n", err)
			return 1
		}
	case "loadexternal":
		if *in == "" || *public == "" {
			fmt.Printf("tpm2genkey: error must specify --in --public  when loading external public key\n")
			return 1
		}

		rwc, err := openTPM(*tpmPath)
		if err != nil {
			fmt.Printf("can't open TPM %v\n", err)
			return 1
		}
		defer func() {
			rwc.Close()
		}()

		rwr := transport.FromReadWriter(rwc)

		ep, err := os.ReadFile(*in)
		if err != nil {
			fmt.Fprintf(os.Stdout, "tpm2genkey: error reading --in publicKey : %v", err)
			return 1
		}

		var ekPububFromPEMTemplate tpm2.TPMTPublic
		block, _ := pem.Decode(ep)
		parsedKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			fmt.Fprintf(os.Stdout, "tpm2genkey:  error parsing public key : %v", err)
			return 1
		}

		switch pub := parsedKey.(type) {
		case *rsa.PublicKey:
			rsaPub, ok := parsedKey.(*rsa.PublicKey)
			if !ok {
				fmt.Fprintf(os.Stdout, "tpm2genkey:  error converting key to rsa")
				return 1
			}
			// todo, support arbitrary templates someday
			ekPububFromPEMTemplate = tpm2.RSAEKTemplate
			ekPububFromPEMTemplate.Parameters = tpm2.NewTPMUPublicParms(
				tpm2.TPMAlgRSA,
				&tpm2.TPMSRSAParms{
					Symmetric: tpm2.TPMTSymDefObject{
						Algorithm: tpm2.TPMAlgAES,
						KeyBits: tpm2.NewTPMUSymKeyBits(
							tpm2.TPMAlgAES,
							tpm2.TPMKeyBits(128),
						),
						Mode: tpm2.NewTPMUSymMode(
							tpm2.TPMAlgAES,
							tpm2.TPMAlgCFB,
						),
					},
					KeyBits:  2048,
					Exponent: uint32(*exponent),
				},
			)
			ekPububFromPEMTemplate.Unique = tpm2.NewTPMUPublicID(
				tpm2.TPMAlgRSA,
				&tpm2.TPM2BPublicKeyRSA{
					Buffer: rsaPub.N.Bytes(),
				},
			)

			// ekPububFromPEMTemplate = tpm2.TPMTPublic{
			// 	Type:    tpm2.TPMAlgRSA,
			// 	NameAlg: tpm2.TPMAlgSHA256,
			// 	ObjectAttributes: tpm2.TPMAObject{
			// 		FixedTPM:             true,
			// 		STClear:              false,
			// 		FixedParent:          true,
			// 		SensitiveDataOrigin:  true,
			// 		UserWithAuth:         false,
			// 		AdminWithPolicy:      true,
			// 		NoDA:                 false,
			// 		EncryptedDuplication: false,
			// 		Restricted:           true,
			// 		Decrypt:              true,
			// 		SignEncrypt:          false,
			// 	},
			// 	AuthPolicy: tpm2.TPM2BDigest{
			// 		Buffer: []byte{
			// 			// TPM2_PolicySecret(RH_ENDORSEMENT)
			// 			0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xB3, 0xF8,
			// 			0x1A, 0x90, 0xCC, 0x8D, 0x46, 0xA5, 0xD7, 0x24,
			// 			0xFD, 0x52, 0xD7, 0x6E, 0x06, 0x52, 0x0B, 0x64,
			// 			0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14, 0x69, 0xAA,
			// 		},
			// 	},
			// 	Parameters: tpm2.NewTPMUPublicParms(
			// 		tpm2.TPMAlgRSA,
			// 		&tpm2.TPMSRSAParms{
			// 			Symmetric: tpm2.TPMTSymDefObject{
			// 				Algorithm: tpm2.TPMAlgAES,
			// 				KeyBits: tpm2.NewTPMUSymKeyBits(
			// 					tpm2.TPMAlgAES,
			// 					tpm2.TPMKeyBits(128),
			// 				),
			// 				Mode: tpm2.NewTPMUSymMode(
			// 					tpm2.TPMAlgAES,
			// 					tpm2.TPMAlgCFB,
			// 				),
			// 			},
			// 			KeyBits:  2048,
			// 			Exponent: uint32(*exponent),
			// 		},
			// 	),
			// 	Unique: tpm2.NewTPMUPublicID(
			// 		tpm2.TPMAlgRSA,
			// 		&tpm2.TPM2BPublicKeyRSA{
			// 			Buffer: rsaPub.N.Bytes(),
			// 		},
			// 	),
			// }

		case *ecdsa.PublicKey:
			ecPub, ok := parsedKey.(*ecdsa.PublicKey)
			if !ok {
				fmt.Fprintf(os.Stdout, "tpm2genkey:  error converting key to ecdsa")
				return 1
			}

			if *parentKeyType == "h2" {
				ekPububFromPEMTemplate = keyfile.ECCSRK_H2_Template
			} else {
				ekPububFromPEMTemplate = tpm2.ECCEKTemplate
			}
			ekPububFromPEMTemplate.Unique = tpm2.NewTPMUPublicID(
				tpm2.TPMAlgECC,
				&tpm2.TPMSECCPoint{
					X: tpm2.TPM2BECCParameter{
						Buffer: ecPub.X.Bytes(),
					},
					Y: tpm2.TPM2BECCParameter{
						Buffer: ecPub.Y.Bytes(),
					},
				},
			)
		default:
			fmt.Fprintf(os.Stdout, "tpm2genkey: unsupported public key type %v", pub)
			return 1
		}

		l, err := tpm2.LoadExternal{
			InPublic:  tpm2.New2B(ekPububFromPEMTemplate),
			Hierarchy: tpm2.TPMRHOwner,
		}.Execute(rwr)
		if err != nil {
			fmt.Fprintf(os.Stdout, "tpm2genkey: error loading key %v", err)
			return 1
		}
		defer func() {
			flush := tpm2.FlushContext{
				FlushHandle: l.ObjectHandle,
			}
			_, err = flush.Execute(rwr)
		}()

		key_TPMTPublic_bytes := tpm2.Marshal(ekPububFromPEMTemplate)
		key_TPM2BPublic := tpm2.BytesAs2B[tpm2.TPM2BPublic](key_TPMTPublic_bytes)
		key_TPM2BPublic_bytes := tpm2.Marshal(key_TPM2BPublic)

		err = os.WriteFile(*public, key_TPM2BPublic_bytes, 0644)
		if err != nil {
			fmt.Printf("tpm2genkey: failed to write public key to file %v\n", err)
			return 1
		}

		n, err := tpm2.ObjectName(&ekPububFromPEMTemplate)
		if err != nil {
			fmt.Printf("tpm2genkey:  to get name key: %v", err)
			return 1
		}
		fmt.Printf("loaded external %s\n", hex.EncodeToString(n.Buffer))

		fmt.Printf("loaded name %s\n", hex.EncodeToString(l.Name.Buffer))

	default:
		fmt.Println("tpm2genkey: Unknown mode: must be create|pem2tpm|tpm2pem|loadexternal")
		return 1
	}
	return 0
}
