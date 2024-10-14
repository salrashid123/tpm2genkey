package main

import (
	"crypto/sha256"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
)

const ()

var (
	tpmPath    = flag.String("tpm-path", "/dev/tpmrm0", "Path to the TPM device (character device or a Unix socket).")
	keyFile    = flag.String("keyfile", "private.pem", "privateKey File")
	dataToSign = flag.String("datatosign", "bar", "data to sign")
	password   = flag.String("password", "", "key password")
	pcrs       = flag.String("pcrs", "", "pcr banks to bind the key to")
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

type TPM struct {
	transport io.ReadWriteCloser
}

func (t *TPM) Send(input []byte) ([]byte, error) {
	return tpmutil.RunCommandRaw(t.transport, input)
}

func getTPM(s io.ReadWriteCloser) (transport.TPMCloser, error) {
	return &TPM{

		transport: s,
	}, nil
}

func (t *TPM) Close() error {
	return t.transport.Close()
}

func main() {
	flag.Parse()

	log.Println("======= Init  ========")

	rwc, err := openTPM(*tpmPath)
	if err != nil {
		log.Fatalf("can't open TPM %q: %v", *tpmPath, err)
	}
	defer func() {
		rwc.Close()
	}()

	// load the rsa key from disk
	log.Printf("======= reading key from file ========")
	c, err := os.ReadFile(*keyFile)
	if err != nil {
		log.Fatalf("error reading private keyfile: %v", err)
	}
	key, err := keyfile.Decode(c)
	if err != nil {
		log.Fatalf("failed decoding key: %v", err)
	}

	rwr, err := getTPM(rwc)
	if err != nil {
		log.Fatalf("failed decoding key: %v", err)
	}

	sess := keyfile.NewTPMSession(rwr)

	//log.Printf("Parent is TPM_HT_PERMANENT: %t", keyfile.IsMSO(tpm2.TPMHandle(key.Parent), keyfile.TPM_HT_PERMANENT))

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

	primary, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: key.Parent,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.New2B(keyfile.ECCSRK_H2_Template),
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("failed loading key with parent: %v", err)
	}
	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: primary.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	parentAuthHandle := tpm2.AuthHandle{
		Handle: primary.ObjectHandle,
		Name:   primary.Name,
		Auth:   tpm2.PasswordAuth(nil),
	}
	ah, err := keyfile.LoadKeyWithParent(sess, parentAuthHandle, key)
	if err != nil {
		log.Fatalf("failed loading key with parent: %v", err)
	}
	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: ah.Handle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	data := []byte(*dataToSign)
	digest := sha256.Sum256(data)

	psess, cleanup1, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16, []tpm2.AuthOption{tpm2.Auth([]byte(*password))}...)
	if err != nil {
		log.Fatalf("setting up trial session: %v", err)
	}
	defer func() {
		if err := cleanup1(); err != nil {
			log.Fatalf("cleaning up trial session: %v", err)
		}
	}()

	tkeyH := tpm2.AuthHandle{
		Handle: ah.Handle,
		Name:   ah.Name,
		Auth:   tpm2.PasswordAuth([]byte(*password)),
	}
	if *pcrs != "" {
		sel := tpm2.TPMLPCRSelection{
			PCRSelections: []tpm2.TPMSPCRSelection{
				{
					Hash:      tpm2.TPMAlgSHA256,
					PCRSelect: tpm2.PCClientCompatible.PCRs(uintpcrs...),
				},
			},
		}

		expectedDigest, err := getExpectedPCRDigest(rwr, sel, tpm2.TPMAlgSHA256)
		if err != nil {
			log.Fatalf("executing getting expecteddigest: %v", err)
		}

		_, err = tpm2.PolicyPCR{
			PolicySession: psess.Handle(),
			Pcrs: tpm2.TPMLPCRSelection{
				PCRSelections: sel.PCRSelections,
			},
			PcrDigest: tpm2.TPM2BDigest{
				Buffer: expectedDigest,
			},
		}.Execute(rwr)
		if err != nil {
			log.Fatalf("executing policyAuthValue: %v", err)
		}

		_, err = tpm2.PolicyAuthValue{
			PolicySession: psess.Handle(),
		}.Execute(rwr)
		if err != nil {
			log.Fatalf("executing policyAuthValue: %v", err)
		}

		tkeyH = tpm2.AuthHandle{
			Handle: ah.Handle,
			Name:   ah.Name,
			Auth:   psess,
		}
	}

	rspSign, err := tpm2.Sign{
		KeyHandle: tkeyH,
		Digest: tpm2.TPM2BDigest{
			Buffer: digest[:],
		},
		InScheme: tpm2.TPMTSigScheme{
			Scheme: tpm2.TPMAlgRSASSA,
			Details: tpm2.NewTPMUSigScheme(
				tpm2.TPMAlgRSASSA,
				&tpm2.TPMSSchemeHash{
					HashAlg: tpm2.TPMAlgSHA256,
				},
			),
		},
		Validation: tpm2.TPMTTKHashCheck{
			Tag: tpm2.TPMSTHashCheck,
		},
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("Failed to Sign: %v", err)
	}

	rsassa, err := rspSign.Signature.Signature.RSASSA()
	if err != nil {
		log.Fatalf("Failed to get signature part: %v", err)
	}
	log.Printf("signature  : %s\n", base64.StdEncoding.EncodeToString(rsassa.Sig.Buffer))
}

func getExpectedPCRDigest(thetpm transport.TPM, selection tpm2.TPMLPCRSelection, hashAlg tpm2.TPMAlgID) ([]byte, error) {
	pcrRead := tpm2.PCRRead{
		PCRSelectionIn: selection,
	}

	pcrReadRsp, err := pcrRead.Execute(thetpm)
	if err != nil {
		return nil, err
	}

	var expectedVal []byte
	for _, digest := range pcrReadRsp.PCRValues.Digests {
		expectedVal = append(expectedVal, digest.Buffer...)
	}

	cryptoHashAlg, err := hashAlg.Hash()
	if err != nil {
		return nil, err
	}

	hash := cryptoHashAlg.New()
	hash.Write(expectedVal)
	return hash.Sum(nil), nil
}
