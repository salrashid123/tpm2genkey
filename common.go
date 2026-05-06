package tpm2genkey

import (
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"hash"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

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

func getPCRMap(algo tpm2.TPMAlgID, pcrMap map[uint][]byte) (map[uint][]byte, []uint, []byte, error) {

	var hsh hash.Hash
	// https://github.com/tpm2-software/tpm2-tools/blob/83f6f8ac5de5a989d447d8791525eb6b6472e6ac/lib/tpm2_openssl.c#L206
	if algo == tpm2.TPMAlgSHA1 {
		hsh = sha1.New()
	}
	if algo == tpm2.TPMAlgSHA256 {
		hsh = sha256.New()
	}

	if algo == tpm2.TPMAlgSHA1 || algo == tpm2.TPMAlgSHA256 {
		for uv, v := range pcrMap {
			pcrMap[uint(uv)] = v
			hsh.Write(v)
		}
	} else {
		return nil, nil, nil, fmt.Errorf("unknown Hash Algorithm for TPM PCRs %v", algo)
	}

	pcrs := make([]uint, 0, len(pcrMap))
	for k := range pcrMap {
		pcrs = append(pcrs, k)
	}

	return pcrMap, pcrs, hsh.Sum(nil), nil
}
