package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"slices"
	"strconv"
	"strings"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"

	"github.com/salrashid123/tpm2genkey/util"
)

/*
This snippet demonstrates `PolicyOr` with three options:

* `PolicyOr( PolicyPCR(23) || PolicyAuthValue(password) || PolicySecret() )`

basically, you create a signing key which is bound by three policies with OR logic

Once the key is defined, to use it, you'll need to fulfill one of those policies (its seems precisely one) and the execute the PolicyOR

The key is formatted with the policy syntax:

```bash
$ openssl asn1parse -in  key.pem

	  0:d=0  hl=4 l= 773 cons: SEQUENCE
	  4:d=1  hl=2 l=   6 prim: OBJECT            :2.23.133.10.1.3
	 12:d=1  hl=3 l= 211 cons: cont [ 1 ]
	 15:d=2  hl=3 l= 208 cons: SEQUENCE
	 18:d=3  hl=2 l=  54 cons: SEQUENCE
	 20:d=4  hl=2 l=   4 cons: cont [ 0 ]
	 22:d=5  hl=2 l=   2 prim: INTEGER           :017F
	 26:d=4  hl=2 l=  46 cons: cont [ 1 ]
	 28:d=5  hl=2 l=  44 prim: OCTET STRING      [HEX DUMP]:002066687AADF862BD776C8FC18B8E9F8E20089714856EE233B3902A591D0D5F292500000001000B03000080
	 74:d=3  hl=2 l=  20 cons: SEQUENCE
	 76:d=4  hl=2 l=   4 cons: cont [ 0 ]
	 78:d=5  hl=2 l=   2 prim: INTEGER           :0151
	 82:d=4  hl=2 l=  12 cons: cont [ 1 ]
	 84:d=5  hl=2 l=  10 prim: OCTET STRING      [HEX DUMP]:4000000B00044000000B
	 96:d=3  hl=2 l=  10 cons: SEQUENCE
	 98:d=4  hl=2 l=   4 cons: cont [ 0 ]
	100:d=5  hl=2 l=   2 prim: INTEGER           :016B
	104:d=4  hl=2 l=   2 cons: cont [ 1 ]
	106:d=5  hl=2 l=   0 prim: OCTET STRING
	108:d=3  hl=2 l= 116 cons: SEQUENCE
	110:d=4  hl=2 l=   4 cons: cont [ 0 ]
	112:d=5  hl=2 l=   2 prim: INTEGER           :0171
	116:d=4  hl=2 l= 108 cons: cont [ 1 ]
	118:d=5  hl=2 l= 106 prim: OCTET STRING      [HEX DUMP]:0000000300203C87A4B3FB85EBEEA58C5FB36AC22D3F280CEC27A9F6DD0FA23BE9CE560DEEC80020837197674484B3F81A90CC8D46A5D724FD52D76E06520B64F2A1DA1B331469AA00208FCD2169AB92694E0C633F1AB772842B8241BBC20288981FC7AC1EDDC1FDDB0E
	226:d=1  hl=2 l=   4 prim: INTEGER           :40000001
	232:d=1  hl=4 l= 314 prim: OCTET STRING      [HEX DUMP]:01380001000B0004003200201B5DB4F6BCB04748CF0E294941E72B29F194CD81BF52B0F3AA14128D95039CD800100014000B080000010001010090C5DF5F8B9602506A7452687BCEF4386FD16F0EE7D14D349E8DDD6332706928812A848EED4809487337A25E052EE72B7CA07027C5C01D1AC25E574AA731B6A75343985AD0E1731B8C8486A64DFD1BF02BABC102A07BF961C12145936F962EB8C86ACFF438C430599E1A6877A6D08FBE08C92860490D8F88A7604C0C89DA3382DF647B3F5360248AF77D72F2B0DF72ECDFDAEAA6AC7A02FD19B3D7041C5BEA79CDFF2345102F45A7EFC6CCEA3C643EF69D09413D6C4CE2745712409409ABC647F66FB3EFD0E898953B47092ECD591B11F826C509DA0A034D2006FEC5E639D39EAE54AE0360E117DFFF2973814A4AFB78D59AA16EC2E1E3B78894427A2CD8500B
	550:d=1  hl=3 l= 224 prim: OCTET STRING      [HEX DUMP]:00DE0020CF1ED0A77546B32845034A6FBF97FEEA719BDBA868800A200C9EC6F6BC97688900102D49B8CDDFF9E687B9D30B64EC1A1AD6140FDC3FF09679496D1D19DFF8FBD02468F9BB8DF29B538218D821B95D28222A785E58D350033FC5234F587A71CC700A45DB2674CB240D2AB427790177EB103FEAA30F7D790C3D027910D9C12B5C4256C5675B568FC18F6EFE744AEFE2009C1C9F4DCD07128C871B17BCCA086AEA314826422FB559FD6639AE56C1199F890F848650F5C2FE90B0394DB282674F2AFA7F2180FC865656748BC3C243FDA907524E322B1648D372BA5EBA18

```

```bash

rm -rf /tmp/myvtpm && mkdir /tmp/myvtpm && swtpm_setup --tpmstate /tmp/myvtpm --tpm2 --create-ek-cert && swtpm socket --tpmstate dir=/tmp/myvtpm --tpm2 --server type=tcp,port=2321 --ctrl type=tcp,port=2322 --flags not-need-init,startup-clear --log level=5

$ go run policysyntax_or/main.go --withPolicyPCR
2026/06/21 08:05:05 ======= Init  ========
2026/06/21 08:05:05 ======= creating key ========
2026/06/21 08:05:05 PolicyPCR Digest portion ONLINE: 3c87a4b3fb85ebeea58c5fb36ac22d3f280cec27a9f6dd0fa23be9ce560deec8
2026/06/21 08:05:05 PolicyPCR Digest portion OFFLINE: 3c87a4b3fb85ebeea58c5fb36ac22d3f280cec27a9f6dd0fa23be9ce560deec8
2026/06/21 08:05:05 PolicySecret Digest portion ONLINE: 837197674484b3f81a90cc8d46a5d724fd52d76e06520b64f2a1da1b331469aa
2026/06/21 08:05:05 PolicySecretDigest portion OFFLINE: 837197674484b3f81a90cc8d46a5d724fd52d76e06520b64f2a1da1b331469aa
2026/06/21 08:05:05 PolicyAuthValue Digest portion ONLINE: 8fcd2169ab92694e0c633f1ab772842b8241bbc20288981fc7ac1eddc1fddb0e
2026/06/21 08:05:05 PolicyAuthValue portion OFFLINE: 8fcd2169ab92694e0c633f1ab772842b8241bbc20288981fc7ac1eddc1fddb0e
2026/06/21 08:05:05 PolicyOr Digest portion ONLINE: 1b5db4f6bcb04748cf0e294941e72b29f194cd81bf52b0f3aa14128d95039cd8
2026/06/21 08:05:05 PolicyOR portion OFFLINE: 1b5db4f6bcb04748cf0e294941e72b29f194cd81bf52b0f3aa14128d95039cd8
-----BEGIN TSS2 PRIVATE KEY-----
MIIDBQYGZ4EFCgEDoYHTMIHQMDagBAICAX+hLgQsACBmaHqt+GK9d2yPwYuOn44g
CJcUhW7iM7OQKlkdDV8pJQAAAAEACwMAAIAwFKAEAgIBUaEMBApAAAALAARAAAAL
MAqgBAICAWuhAgQAMHSgBAICAXGhbARqAAAAAwAgPIeks/uF6+6ljF+zasItPygM
7Cep9t0PojvpzlYN7sgAIINxl2dEhLP4GpDMjUal1yT9UtduBlILZPKh2hszFGmq
ACCPzSFpq5JpTgxjPxq3coQrgkG7wgKImB/HrB7dwf3bDgIEQAAAAQSCAToBOAAB
AAsABAAyACAbXbT2vLBHSM8OKUlB5ysp8ZTNgb9SsPOqFBKNlQOc2AAQABQACwgA
AAEAAQEA44DEraE3ix3kdQljWbKs5TJ6bJbKM6Dv8m2GUEG4cRi63Hl5nFmwhXku
6B8uYihea05MbZb35BSgZqdMen1gl00agYvZyCafv4xIgRIBE/s4LRJ6iW7mmse3
jQ/CBXGO290RxaaV4zYkyl8zeEsK4HsRfN9XoJ/xL//w6VfXxdAJob1ztPRA/PcR
a8aLQRZfvt5vQU9oEnBMbey/wCQqx9uoLnhL7SX0lMMhW4dDlzOMvj/ZobPPsgsS
6PgQZPC+uQpLaLvCZc2QTfgxSPWQpHHqsxehkSjtjOWLnWC3LHtKPDEdEGaUwRIl
XBPAzEtMBfCyXT++S10QWnhaUFyG3wSB4ADeACDckvTqOdlRlx2plPFM6Peeycqn
BZ1orPDUPZPwGL/6dwAQze5bs1Y/PDMIT6dEzrjfk32jJnIK+94/CZPec8hIEEez
tjc7ZQqIAIIMu0yLGsDhN03+gvfp0Zcgp48kLp5uAc6LtAYeBFhEPV3Zs5k1B1Hw
kWhc6l8IrlJRO+bhCkTDcw0FzHexuyAHC/T6lRYilPNeZXrT1yzaZ15UeMF4CJDA
8zNzye/pdFd1FGnNJQfOYoipzt2LcpiJfzvX86+SKQHlgL+rD79AOuudiAx9Nw8n
UpGnzc4o4Dvc
-----END TSS2 PRIVATE KEY-----

2026/06/21 08:05:05 =======  key created ========
PolicyPCR
skip PolicySecret
Skip PolicyAuthValue
PolicyOr
2026/06/21 08:05:05 signature  : s2jNGB81IhyPzFJeyiSTKh9fU+d9zYy3se4hlC3/c36SEx2+y3+bKLpUpfE1wd0GQc8aqcEFPGVaRUAF/IIYB4fbCrL2p6DPkoT0JXLefI4xy60AdERlC3QV2NT34UBWZSo7k2dTPviR3LN7/ENtvoiisvreiKyR1LNos8GvcCiIWZVvGF7Z2yH52QMgfEHKliEzvgsDT2p4bWylwHW82FoB36O+5jWkyEgMWlwyhn3QkBz0mGQcF9WVXf9XZKV4lK+n83A+GdiMUVok3SLob8/SvtT4+3a9twD/aEOOCHOx9uMDidfmH0YKvOjpbTQtVEZPvAwJekhrXhf2CR2k1Q==

$ go run policysyntax_or/main.go -withPolicySecret
2026/06/21 08:05:08 ======= Init  ========
2026/06/21 08:05:08 ======= creating key ========
2026/06/21 08:05:08 PolicyPCR Digest portion ONLINE: 3c87a4b3fb85ebeea58c5fb36ac22d3f280cec27a9f6dd0fa23be9ce560deec8
2026/06/21 08:05:08 PolicyPCR Digest portion OFFLINE: 3c87a4b3fb85ebeea58c5fb36ac22d3f280cec27a9f6dd0fa23be9ce560deec8
2026/06/21 08:05:08 PolicySecret Digest portion ONLINE: 837197674484b3f81a90cc8d46a5d724fd52d76e06520b64f2a1da1b331469aa
2026/06/21 08:05:08 PolicySecretDigest portion OFFLINE: 837197674484b3f81a90cc8d46a5d724fd52d76e06520b64f2a1da1b331469aa
2026/06/21 08:05:08 PolicyAuthValue Digest portion ONLINE: 8fcd2169ab92694e0c633f1ab772842b8241bbc20288981fc7ac1eddc1fddb0e
2026/06/21 08:05:08 PolicyAuthValue portion OFFLINE: 8fcd2169ab92694e0c633f1ab772842b8241bbc20288981fc7ac1eddc1fddb0e
2026/06/21 08:05:08 PolicyOr Digest portion ONLINE: 1b5db4f6bcb04748cf0e294941e72b29f194cd81bf52b0f3aa14128d95039cd8
2026/06/21 08:05:08 PolicyOR portion OFFLINE: 1b5db4f6bcb04748cf0e294941e72b29f194cd81bf52b0f3aa14128d95039cd8
-----BEGIN TSS2 PRIVATE KEY-----
MIIDBQYGZ4EFCgEDoYHTMIHQMDagBAICAX+hLgQsACBmaHqt+GK9d2yPwYuOn44g
CJcUhW7iM7OQKlkdDV8pJQAAAAEACwMAAIAwFKAEAgIBUaEMBApAAAALAARAAAAL
MAqgBAICAWuhAgQAMHSgBAICAXGhbARqAAAAAwAgPIeks/uF6+6ljF+zasItPygM
7Cep9t0PojvpzlYN7sgAIINxl2dEhLP4GpDMjUal1yT9UtduBlILZPKh2hszFGmq
ACCPzSFpq5JpTgxjPxq3coQrgkG7wgKImB/HrB7dwf3bDgIEQAAAAQSCAToBOAAB
AAsABAAyACAbXbT2vLBHSM8OKUlB5ysp8ZTNgb9SsPOqFBKNlQOc2AAQABQACwgA
AAEAAQEA0eFWustrwMZf5rwmCb5X9QhSJjpg0rGF+nDEi+t53lqihfA2HCvxlGpP
7iNsIvMyPKrExHebR4LpDzwG8ToXlLzCi8zkbkROzyV9jP/Oq7VYJL/NlHrijaV9
6MItSFkB85dlLrYcPicZHNzQsLNtnDcx+jZ1yIhuOCfXf592r5Mq4VNMpFmd4j6q
TccW31qH/AbteKpYR9hrOAVKKIH8k3xKG8Pu8BVKKk2rR8LajCQGA5Llqmpzcwc2
13EAHxaAEoEynCVzCEdS7vIoIwLGwGJbxyMAEzXmdmYOxBz9Yc/p5KaS+/ePTALy
5CWeT3665ErbXLSxAvmySbhqBQnlmwSB4ADeACAz0QRHPSNMWBoAbDmCvT+BbyWi
VKx6eYsuB/NTqOOqHQAQIwLD4D4VLMyOSlfDE4NJYX1Qj1UUjwI1SpmORh4Yegic
EaaMjNyowuqKq0fWq9uGMvtT3xnurg5J1L7dDzkWB/ZZ4F8ByTRIcgQpsveykaP2
55oeov7qCHMRCBMH/Dv13fUKolkB+WI3+EhSF1A+Nq5zzidzo71lldD01SZHhTMJ
OnqcaP6cy4nhlDyH85Y3Ckv8pQueVQh8KGYPREy4W68RUVp1VppEsQdhbue2OH3Q
CGuGB6vvcjvU
-----END TSS2 PRIVATE KEY-----

2026/06/21 08:05:08 =======  key created ========
PolicySecret
skip PolicyPCR
Skip PolicyAuthValue
PolicyOr
2026/06/21 08:05:08 signature  : wQFKlLYvXRUtW2E/VsmNbKVOBRfeOkmdGugptnPzGprfs2Lhn8M18FvmWL4R+xEWnxJuzO9wargXsXURUczJHci6N/N0ciqtVnNbMQtT1x96n8xztyKCcgZCAWOBVfHmWmuN/cFhiQvGBVYrUrrUg/lgCWQiFety3RifeJwdxp8H5D1EcLp840JVmZ05YhWogk0XYZcM8OtOa4Zrd1lIUOut1qY2TBUU2Qm/re8nCh9PPfYA+2nQEf9/ros0o7xI1mo2fEA0YHN0b5p9m282oXC0kHNi8i+YwLGnC99Q9DhJ8WDaWR5HqMyxKrjpq457E6ezpExH+Dm9/sVRnjq2Zw==

$ go run policysyntax_or/main.go -withPolicyAuthValue
2026/06/21 08:05:16 ======= Init  ========
2026/06/21 08:05:16 ======= creating key ========
2026/06/21 08:05:16 PolicyPCR Digest portion ONLINE: 3c87a4b3fb85ebeea58c5fb36ac22d3f280cec27a9f6dd0fa23be9ce560deec8
2026/06/21 08:05:16 PolicyPCR Digest portion OFFLINE: 3c87a4b3fb85ebeea58c5fb36ac22d3f280cec27a9f6dd0fa23be9ce560deec8
2026/06/21 08:05:16 PolicySecret Digest portion ONLINE: 837197674484b3f81a90cc8d46a5d724fd52d76e06520b64f2a1da1b331469aa
2026/06/21 08:05:16 PolicySecretDigest portion OFFLINE: 837197674484b3f81a90cc8d46a5d724fd52d76e06520b64f2a1da1b331469aa
2026/06/21 08:05:16 PolicyAuthValue Digest portion ONLINE: 8fcd2169ab92694e0c633f1ab772842b8241bbc20288981fc7ac1eddc1fddb0e
2026/06/21 08:05:16 PolicyAuthValue portion OFFLINE: 8fcd2169ab92694e0c633f1ab772842b8241bbc20288981fc7ac1eddc1fddb0e
2026/06/21 08:05:16 PolicyOr Digest portion ONLINE: 1b5db4f6bcb04748cf0e294941e72b29f194cd81bf52b0f3aa14128d95039cd8
2026/06/21 08:05:16 PolicyOR portion OFFLINE: 1b5db4f6bcb04748cf0e294941e72b29f194cd81bf52b0f3aa14128d95039cd8
-----BEGIN TSS2 PRIVATE KEY-----
MIIDBQYGZ4EFCgEDoYHTMIHQMDagBAICAX+hLgQsACBmaHqt+GK9d2yPwYuOn44g
CJcUhW7iM7OQKlkdDV8pJQAAAAEACwMAAIAwFKAEAgIBUaEMBApAAAALAARAAAAL
MAqgBAICAWuhAgQAMHSgBAICAXGhbARqAAAAAwAgPIeks/uF6+6ljF+zasItPygM
7Cep9t0PojvpzlYN7sgAIINxl2dEhLP4GpDMjUal1yT9UtduBlILZPKh2hszFGmq
ACCPzSFpq5JpTgxjPxq3coQrgkG7wgKImB/HrB7dwf3bDgIEQAAAAQSCAToBOAAB
AAsABAAyACAbXbT2vLBHSM8OKUlB5ysp8ZTNgb9SsPOqFBKNlQOc2AAQABQACwgA
AAEAAQEAoMsxT/rr22DYimmxEkoIIWtD0GGXWFoKD1Sn4j69itbrlUp4Wg5t7rhy
jcOQRsmDxNCkeqmG30g/y9n75N/soDgqBiCh8tRloD/NMc+Bxjg3Dpgkbjd1svWf
DeXr/sLzTb6b3admomDTmXPChP5RlnsNSvv7UCUTuah32a9r2bJBt9eIhOdsesce
Ah3pPGfKiOP8ANSD61bEjToKTCWxFcLJytsdtFkCzrQsjDIBOtkHXopEViK43g1J
1YY0lWzY+NLazHOyLkgfvIpH53sZsutRBuskXX9utSRMs//KShk258FFukCBPsxO
kCjdGdtJqPYFvMvyglZp+ifLCI3PYQSB4ADeACDI/Kc94OEDiPwPTAGH33iBnmB/
pHdFyT6/opeLBtKDMgAQ5RPl8HZrMXY8jayAX5h/JeERxCaeesT/qDVzYdqP3NjC
VuD1OBeB5CfahoJYL9J456XWbyQyvs3j5lw0/B7b7ltsybQ8sCJ76e1IWRw6wXex
7q7W1yXDBcfGtNBHpiU0fPWeuSdv97y8pJ+OdC/q0IKceJy+fGjxYfU9vMWHED8g
+XA8M1Oalegr8s+C241gREfvhdseQqwAHkC3HUP0Ct1RoqrZLh8JBO4YCEz1s3FC
4my1DzhUQ/L6
-----END TSS2 PRIVATE KEY-----

2026/06/21 08:05:17 =======  key created ========
PolicyAuthValue
Skip PolicyPCR
skip PolicySecret
PolicyAuthValue
PolicyOr
2026/06/21 08:05:17 signature  : gs8aiz7dbvV0uXrwZhBRfn/gKU6wXQNQAKDCmiMUdQuUhx0f7Nv5EDgFCnl7rgFyTP7MctYTzBmq1rdkBSufTqB4m+PdKX7pJySsNvJx01puihVVs6T0wZNY6gFBFwbJdnfqjxHdcyeAJJ1sIjuFN0Ey6kp0ZCgDlkE2xKh+yMZ8Rw9I3a8E68bBKBgaQihXvMsUc3tgwUqrBX8gSDdq9EGPvNiIOzKknjRT/4g2pJl6oobX0PMhd9aQTqv2cfBb/uKP1I/jX0o8Ve7qOOkhEB9sGui3smLwTPRoCDZHAB400XivnWvo6ktanHA14XRpkDb3NREh8Y9G4FFaTHnbIg==
```
*/
const ()

var (
	tpmPath             = flag.String("tpm-path", "127.0.0.1:2321", "Path to the TPM device (character device or a Unix socket).")
	keyFile             = flag.String("keyfile", "private.pem", "privateKey File")
	dataToSign          = flag.String("datatosign", "bar", "data to sign")
	password            = flag.String("password", "bar", "key password")
	pcrs                = flag.String("pcrs", "23", "pcr banks to bind the key to")
	withPolicyPCR       = flag.Bool("withPolicyPCR", false, "test policyPCR")
	withPolicyAuthValue = flag.Bool("withPolicyAuthValue", false, "test policyAuthValue (password)")
	withPolicySecret    = flag.Bool("withPolicySecret", false, "test withPolicySecret")
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

	if *withPolicyAuthValue == false && *withPolicyPCR == false && *withPolicySecret == false {
		log.Fatal("one of --withPolicyAuthValue --withPolicyPCR --withPolicySecret must be set ")
	}

	rwc, err := openTPM(*tpmPath)
	if err != nil {
		log.Fatalf("can't open TPM %q: %v", *tpmPath, err)
	}
	defer func() {
		rwc.Close()
	}()

	log.Printf("======= creating key ========")

	rwr := transport.FromReadWriter(rwc)

	// First get the policy digest for PolicyPCR either
	// 1. online which requires a TPM
	// 2. Offline wich manually calculates the digest

	sess_pcr, cleanup1_pcr, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16, []tpm2.AuthOption{tpm2.Trial(), tpm2.AESEncryption(128, tpm2.EncryptIn), tpm2.AESEncryption(128, tpm2.EncryptOut)}...)
	if err != nil {
		log.Fatalf("setting up trial session: %v", err)
	}
	defer cleanup1_pcr()

	uintpcrs := make([]uint, len(strings.Split(*pcrs, ",")))
	for idx, i := range strings.Split(*pcrs, ",") {
		if i != "" {
			j, err := strconv.Atoi(i)
			if err != nil {
				log.Fatalf("tpm2genkey: error converting pcr list  %v\n", err)

			}
			uintpcrs[idx] = uint(j)
		}
	}

	// policy PCR
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
		log.Fatalf("ERROR:  could not get PolicySession: %v", err)
	}

	policy_pcr_struct_online := tpm2.PolicyPCR{
		PolicySession: sess_pcr.Handle(),
		Pcrs: tpm2.TPMLPCRSelection{
			PCRSelections: sel.PCRSelections,
		},
		PcrDigest: tpm2.TPM2BDigest{
			Buffer: expectedDigest,
		},
	}
	// START execute the policyPCR to get the online verion
	// online calculator
	_, err = policy_pcr_struct_online.Execute(rwr)
	if err != nil {
		log.Fatalf("error executing PolicyPCR: %v", err)
	}

	pcr_digest_online, err := tpm2.PolicyGetDigest{
		PolicySession: sess_pcr.Handle(),
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("error executing PolicyGetDigest PolicyPCR: %v", err)
	}

	log.Printf("PolicyPCR Digest ONLINE: %s\n", hex.EncodeToString(pcr_digest_online.PolicyDigest.Buffer))
	// calculate the command parameter
	commandParameterPCR, err := util.CPBytes(policy_pcr_struct_online)
	if err != nil {
		log.Fatalf("error getting policy command bytes PolicyPCR: %v", err)
	}

	err = cleanup1_pcr()
	if err != nil {
		log.Fatalf("error clearing policyPCR %v", err)
	}
	// END execute the policyPCR to get the online verion

	// START execute the policyPCR to get the OFFLINE verion
	policy_pcr_struct_offline := tpm2.PolicyPCR{
		Pcrs: tpm2.TPMLPCRSelection{
			PCRSelections: sel.PCRSelections,
		},
		PcrDigest: tpm2.TPM2BDigest{
			Buffer: expectedDigest,
		},
	}

	policypcrCalculator, err := tpm2.NewPolicyCalculator(tpm2.TPMAlgSHA256)
	if err != nil {
		log.Fatalf("error setting up NewPolicyCalculator for PolicyPCR : %v", err)
	}
	err = policy_pcr_struct_offline.Update(policypcrCalculator)
	if err != nil {
		log.Fatalf("error updating NewPolicyCalculator for PolicyPCR %v", err)
	}

	log.Printf("PolicyPCR Digest OFFLINE: %s\n", hex.EncodeToString(policypcrCalculator.Hash().Digest))
	// END execute the policyPCR to get the OFFLINE verion

	//********************'
	// START execute the policySecret to get the OFFLINE verion

	sess_secret, cleanup1_secret, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16, []tpm2.AuthOption{tpm2.Trial(), tpm2.AESEncryption(128, tpm2.EncryptIn), tpm2.AESEncryption(128, tpm2.EncryptOut)}...)
	if err != nil {
		log.Fatalf("setting up trial session: %v", err)
	}
	defer cleanup1_secret()
	pol_secret_struct_online := tpm2.PolicySecret{
		PolicySession: sess_secret.Handle(),
		AuthHandle:    tpm2.TPMRHEndorsement,
	}

	_, err = pol_secret_struct_online.Execute(rwr)
	if err != nil {
		log.Fatalf("error executing PolicySecret: %v", err)
	}

	policy_secret_digest_online, err := tpm2.PolicyGetDigest{
		PolicySession: sess_secret.Handle(),
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("error executing PolicyPCR: %v", err)
	}
	log.Printf("PolicySecret Digest ONLINE: %s\n", hex.EncodeToString(policy_secret_digest_online.PolicyDigest.Buffer))

	commandParametersecret, err := util.CPBytes(pol_secret_struct_online)
	if err != nil {
		log.Fatalf("error getting policy command bytes: %v", err)
	}

	err = cleanup1_secret()
	if err != nil {
		log.Fatalf("error clearing policySecret %v", err)
	}

	// offline caclulator
	pol_secret_struct_offline := tpm2.PolicySecret{
		AuthHandle: tpm2.TPMRHEndorsement,
	}
	policysecretCalculator, err := tpm2.NewPolicyCalculator(tpm2.TPMAlgSHA256)
	if err != nil {
		log.Fatalf("error setting up NewPolicyCalculator for PolicySecretValue : %v", err)
	}
	err = pol_secret_struct_offline.Update(policysecretCalculator)
	if err != nil {
		log.Fatalf("error updating NewPolicyCalculator for PolicySecretValue %v", err)
	}

	log.Printf("PolicySecret Digest OFFLINE: %s\n", hex.EncodeToString(policysecretCalculator.Hash().Digest))
	// END execute the policySecret to get the OFFLINE verion

	// *************

	// policy auth value

	sess_authValue, cleanup1_av, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16, []tpm2.AuthOption{tpm2.Trial(), tpm2.AESEncryption(128, tpm2.EncryptIn), tpm2.AESEncryption(128, tpm2.EncryptOut)}...)
	if err != nil {
		log.Fatalf("setting up trial session: %v", err)
	}
	defer cleanup1_av()

	policy_auth_value_struct_online := tpm2.PolicyAuthValue{
		PolicySession: sess_authValue.Handle(),
	}
	_, err = policy_auth_value_struct_online.Execute(rwr)
	if err != nil {
		log.Fatalf("error executing PolicyAuthValue: %v", err)
	}

	policy_auth_value_digest_online, err := tpm2.PolicyGetDigest{
		PolicySession: sess_authValue.Handle(),
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("error executing PolicyPCR: %v", err)
	}
	commandParameterAuth, err := util.CPBytes(policy_auth_value_struct_online)
	if err != nil {
		log.Fatalf("error getting policy command bytes: %v", err)
	}
	err = cleanup1_av()
	if err != nil {
		log.Fatalf("error cleaning  session: %v", err)
	}
	log.Printf("PolicyAuthValue Digest ONLINE: %s\n", hex.EncodeToString(policy_auth_value_digest_online.PolicyDigest.Buffer))

	// END execute the PolicyAuthValue to get the OFFLINE verion

	//********************'
	// START execute the PolicyAuthValue to get the OFFLINE verion

	policy_auth_value_struct_offline := tpm2.PolicyAuthValue{}
	policyauthValueCalculator, err := tpm2.NewPolicyCalculator(tpm2.TPMAlgSHA256)
	if err != nil {
		log.Fatalf("error setting up NewPolicyCalculator for PolicyAuthValue : %v", err)
	}
	err = policy_auth_value_struct_offline.Update(policyauthValueCalculator)
	if err != nil {
		log.Fatalf("error updating NewPolicyCalculator for PolicyAuthValue %v", err)
	}

	log.Printf("PolicyAuthValue Digest OFFLINE: %s\n", hex.EncodeToString(policyauthValueCalculator.Hash().Digest))

	// END execute the policyAuthValue to get the OFFLINE verion

	//
	// policy OR

	csess_or, cleanup1_or, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16, []tpm2.AuthOption{tpm2.Trial(), tpm2.AESEncryption(128, tpm2.EncryptIn), tpm2.AESEncryption(128, tpm2.EncryptOut)}...)
	if err != nil {
		log.Fatalf("setting up trial session: %v", err)
	}
	defer cleanup1_or()

	//online calculator
	policy_or_struct_online := tpm2.PolicyOr{
		PolicySession: csess_or.Handle(),
		PHashList:     tpm2.TPMLDigest{Digests: []tpm2.TPM2BDigest{tpm2.TPM2BDigest{Buffer: pcr_digest_online.PolicyDigest.Buffer}, tpm2.TPM2BDigest{Buffer: policy_secret_digest_online.PolicyDigest.Buffer}, tpm2.TPM2BDigest{Buffer: policy_auth_value_digest_online.PolicyDigest.Buffer}}},
	}
	_, err = policy_or_struct_online.Execute(rwr)
	if err != nil {
		log.Fatalf("error executing PolicyOR: %v", err)
	}

	policy_or_digest_online, err := tpm2.PolicyGetDigest{
		PolicySession: csess_or.Handle(),
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("error executing PolicyOr: %v", err)
	}
	log.Printf("PolicyOr Digest ONLINE: %s\n", hex.EncodeToString(policy_or_digest_online.PolicyDigest.Buffer))

	//offline calculator
	policy_or_struct_offline := tpm2.PolicyOr{
		PHashList: tpm2.TPMLDigest{Digests: []tpm2.TPM2BDigest{tpm2.TPM2BDigest{Buffer: policypcrCalculator.Hash().Digest}, tpm2.TPM2BDigest{Buffer: policysecretCalculator.Hash().Digest}, tpm2.TPM2BDigest{Buffer: policyauthValueCalculator.Hash().Digest}}},
	}
	policyOrCalculator, err := tpm2.NewPolicyCalculator(tpm2.TPMAlgSHA256)
	if err != nil {
		log.Fatalf("error setting up NewPolicyCalculator for policyOR: %v", err)
	}

	err = policy_or_struct_offline.Update(policyOrCalculator)
	if err != nil {
		log.Fatalf("error updating NewPolicyCalculator for policyOR: %v", err)
	}
	log.Printf("PolicyOr Digest OFFLINE: %s\n", hex.EncodeToString(policyOrCalculator.Hash().Digest))

	commandParameterOR, err := util.CPBytes(policy_or_struct_offline)
	if err != nil {
		log.Fatalf("error creating cpbytes PolicyOr: %v", err)
	}

	// create the key template and apply the AuthPolicy digest
	keyTemplate := tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			SignEncrypt:         true,
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        false,
		},
		AuthPolicy: tpm2.TPM2BDigest{
			//Buffer: policy_or_digest_online.PolicyDigest.Buffer, // online
			Buffer: policyOrCalculator.Hash().Digest, // offline
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Scheme: tpm2.TPMTRSAScheme{
					Scheme: tpm2.TPMAlgRSASSA,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgRSASSA,
						&tpm2.TPMSSigSchemeRSASSA{
							HashAlg: tpm2.TPMAlgSHA256,
						},
					),
				},
				KeyBits:  tpm2.TPMKeyBits(2048),
				Exponent: uint32(65537),
			},
		),
	}

	// now create the TPM Policy in order
	var pol []*keyfile.TPMPolicy

	pol = append(pol, &keyfile.TPMPolicy{
		CommandCode:   int(tpm2.TPMCCPolicyPCR),
		CommandPolicy: commandParameterPCR,
	})

	pol = append(pol, &keyfile.TPMPolicy{
		CommandCode:   int(tpm2.TPMCCPolicySecret),
		CommandPolicy: commandParametersecret,
	})

	pol = append(pol, &keyfile.TPMPolicy{
		CommandCode:   int(tpm2.TPMCCPolicyAuthValue),
		CommandPolicy: commandParameterAuth,
	})

	pol = append(pol, &keyfile.TPMPolicy{
		CommandCode:   int(tpm2.TPMCCPolicyOR),
		CommandPolicy: commandParameterOR,
	})

	// create the primary key
	cprimary, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMHandle(uint(tpm2.TPMRHOwner.HandleValue())),
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.New2B(keyfile.ECCSRK_H2_Template),
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: nil,
				},
			},
		},
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("tpm2-genkey: can't create primary: %v", err)
	}

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: cprimary.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	// now create the actual key
	keyresponse, err := tpm2.Create{
		ParentHandle: tpm2.AuthHandle{
			Handle: cprimary.ObjectHandle,
			Name:   cprimary.Name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.New2B(keyTemplate),
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: []byte(*password),
				},
			},
		},
	}.Execute(rwr)
	if err != nil {
		log.Fatalf("tpm2-genkey: can't create key: %v", err)
	}

	// create the key file and include the policy
	kf := keyfile.NewTPMKey(
		keyfile.OIDLoadableKey,
		keyresponse.OutPublic,
		keyresponse.OutPrivate,
		keyfile.WithParent(tpm2.TPMHandle(uint(tpm2.TPMRHOwner.HandleValue()))),
		keyfile.WithUserAuth([]byte(*password)),
		keyfile.WithPolicy(pol),
	)

	keyFileBytes := new(bytes.Buffer)
	err = keyfile.Encode(keyFileBytes, kf)
	if err != nil {
		log.Fatalf("tpm2-genkey: can't create key bytes: %v", err)
	}

	fmt.Printf("%s\n", keyFileBytes)
	flushContextCmdc := tpm2.FlushContext{
		FlushHandle: cprimary.ObjectHandle,
	}
	_, err = flushContextCmdc.Execute(rwr)
	if err != nil {
		log.Fatalf("failed clear the primary key: %v", err)
	}
	//cleanup1()

	log.Printf("=======  key created ========")
	key, err := keyfile.Decode(keyFileBytes.Bytes())
	if err != nil {
		log.Fatalf("failed decoding key: %v", err)
	}

	// ########################################## Load and Sign

	// now load the key, recreate the policies required and then sign
	rwrc, err := getTPM(rwc)
	if err != nil {
		log.Fatalf("failed decoding key: %v", err)
	}
	sess := keyfile.NewTPMSession(rwrc)
	sess.SetOpt(tpm2.Password([]byte(nil)))

	// create the pimary
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

	// now create the policy ans sign
	var sess_or tpm2.Session
	var cleanup_or func() error

	// *************************

	if *withPolicyAuthValue {
		fmt.Println("PolicyAuthValue")
		sess_or, cleanup_or, err = tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16, []tpm2.AuthOption{tpm2.Auth([]byte(*password))}...)
		if err != nil {
			log.Fatalf("Failed to Sign: %v", err)
		}
		defer cleanup_or()
		for _, ppol := range pol {
			switch cc := ppol.CommandCode; cc {
			case int(tpm2.TPMCCPolicyPCR):
				fmt.Println("Skip PolicyPCR")
			case int(tpm2.TPMCCPolicyOR):
				fmt.Println("PolicyOr")
				policy := &tpm2.PolicyOr{
					PolicySession: sess_or.Handle(),
				}
				err = util.ReqParameters(ppol.CommandPolicy, policy)
				if err != nil {
					log.Fatalf("setting up PolicyOr reqparams: %v", err)
				}
				_, err = policy.Execute(rwr)
				if err != nil {
					log.Fatalf("setting up PolicyOr execute: %v", err)
				}
			case int(tpm2.TPMCCPolicySecret):
				fmt.Println("Skip PolicySecret")
			case int(tpm2.TPMCCPolicyAuthValue):
				fmt.Println("PolicyAuthValue")
				policy := &tpm2.PolicyAuthValue{
					PolicySession: sess_or.Handle(),
				}
				_, err = policy.Execute(rwr)
				if err != nil {
					log.Fatalf("setting up policyauthvalue: %v", err)
				}
			default:
				log.Fatalf("unsupported polciy %v", cc)
			}
		}
	}

	if *withPolicyPCR {
		fmt.Println("PolicyPCR")
		sess_or, cleanup_or, err = tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16)
		if err != nil {
			log.Fatalf("setting up trial session: %v", err)
		}
		defer cleanup_or()
		for _, ppol := range pol {
			switch cc := ppol.CommandCode; cc {
			case int(tpm2.TPMCCPolicyPCR):
				policy := &tpm2.PolicyPCR{
					PolicySession: sess_or.Handle(),
				}
				err = util.ReqParameters(ppol.CommandPolicy, policy)
				if err != nil {
					log.Fatalf("setting up policypcr: %v", err)
				}

				_, err = policy.Execute(rwr)
				if err != nil {
					log.Fatalf("setting up policypcr: %v", err)
				}
			case int(tpm2.TPMCCPolicySecret):
				fmt.Println("Skip PolicySecret")

			case int(tpm2.TPMCCPolicyOR):
				fmt.Println("PolicyOr")
				policy := &tpm2.PolicyOr{
					PolicySession: sess_or.Handle(),
				}
				err = util.ReqParameters(ppol.CommandPolicy, policy)
				if err != nil {
					log.Fatalf("setting up PolicyOr reqparams: %v", err)
				}
				_, err = policy.Execute(rwr)
				if err != nil {
					log.Fatalf("setting up PolicyOr execute: %v", err)
				}

			case int(tpm2.TPMCCPolicyAuthValue):
				fmt.Println("Skip PolicyAuthValue")

			default:
				log.Fatalf("unsupported polciy %v", cc)
			}
		}
	}

	if *withPolicySecret {
		fmt.Println("PolicySecret")
		sess_or, cleanup_or, err = tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16)
		if err != nil {
			log.Fatalf("setting up trial session: %v", err)
		}
		defer cleanup_or()
		for _, ppol := range pol {
			switch cc := ppol.CommandCode; cc {
			case int(tpm2.TPMCCPolicyPCR):
				fmt.Println("Skip PolicyPCR")
			case int(tpm2.TPMCCPolicySecret):
				policy := &tpm2.PolicySecret{
					PolicySession: sess_or.Handle(),
				}

				ps, err := util.ReqParametersPolicySecret(ppol.CommandPolicy, policy)
				if err != nil {
					log.Fatalf("error generating requestParameters: %v", err)
				}

				_, err = ps.Execute(rwr)
				if err != nil {
					log.Fatalf("error generating requestParameters: %v", err)
				}

			case int(tpm2.TPMCCPolicyOR):
				fmt.Println("PolicyOr")
				policy := &tpm2.PolicyOr{
					PolicySession: sess_or.Handle(),
				}
				err = util.ReqParameters(ppol.CommandPolicy, policy)
				if err != nil {
					log.Fatalf("setting up PolicyOr reqparams: %v", err)
				}
				_, err = policy.Execute(rwr)
				if err != nil {
					log.Fatalf("setting up PolicyOr execute: %v", err)
				}

			case int(tpm2.TPMCCPolicyAuthValue):
				fmt.Println("Skip PolicyAuthValue")

			default:
				log.Fatalf("unsupported polciy %v", cc)
			}
		}
	}

	var tkeyH tpm2.AuthHandle

	if len(key.Policy) == 0 || key.EmptyAuth {
		tkeyH = tpm2.AuthHandle{
			Handle: ah.Handle,
			Name:   ah.Name,
			Auth:   tpm2.PasswordAuth(nil),
		}
	} else {
		tkeyH = tpm2.AuthHandle{
			Handle: ah.Handle,
			Name:   ah.Name,
			Auth:   sess_or,
		}
	}

	data := []byte(*dataToSign)
	digest := sha256.Sum256(data)

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
