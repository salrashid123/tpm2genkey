package tpm2genkey

import (
	"bytes"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm/tpm2"
)

const ()

var ()

type ToPEMConfig struct {
	Debug       bool   // debug logging
	Public      []byte // TPM2B_PUBLIC
	Private     []byte // TPM2B_PRIVATE
	Parent      uint32 // Parent handle
	Password    []byte // auth password
	Description string
	Policy      []*keyfile.TPMPolicy     // TPM Policy
	AuthPolicy  []*keyfile.TPMAuthPolicy // TPM AuthPolicy
}

type FromPEMConfig struct {
	PEM []byte
}

// [TPM2B_PUBLIC, TPM2B_PRIVATE] -> PEM
func ToPEM(h *ToPEMConfig) ([]byte, error) {

	// todo: validate input

	mtpublic, err := tpm2.Unmarshal[tpm2.TPM2BPublic](h.Public)
	if err != nil {
		return nil, err
	}
	p, err := mtpublic.Contents()
	if err != nil {
		return nil, err
	}

	mtprivate, err := tpm2.Unmarshal[tpm2.TPM2BPrivate](h.Private)
	if err != nil {
		return nil, err
	}

	emptyAuth := true
	if len(h.Password) > 0 {
		emptyAuth = false
	}

	kf := &keyfile.TPMKey{
		Keytype:   keyfile.OIDLoadableKey,
		EmptyAuth: emptyAuth,
		Parent:    tpm2.TPMHandle(h.Parent),
		Pubkey:    tpm2.New2B[tpm2.TPMTPublic, *tpm2.TPMTPublic](*p),
		Privkey: tpm2.TPM2BPrivate{
			Buffer: mtprivate.Buffer,
		},
		Description: h.Description,
		Policy:      h.Policy,
		AuthPolicy:  h.AuthPolicy,
	}
	if err != nil {
		return nil, err
	}

	keyFileBytes := new(bytes.Buffer)
	err = keyfile.Encode(keyFileBytes, kf)
	if err != nil {
		return nil, err
	}

	return keyFileBytes.Bytes(), nil
}

// PEM -> [TPM2B_PUBLIC, TPM2B_PRIVATE]
func FromPEM(h *FromPEMConfig) (*keyfile.TPMKey, []byte, []byte, error) {

	kf, err := keyfile.Decode(h.PEM)
	if err != nil {
		return nil, nil, nil, err
	}
	// todo, optionally print info about the key itself to help using the key.pub, key.prv
	//  eg, print 	kf.Parent  and if its a permanent handle, then probably create a new primary with h2 template
	//  and use that to load the keys  (thats if the user done't have the oringial primary.ctx handy)
	return kf, tpm2.Marshal(kf.Pubkey), tpm2.Marshal(kf.Privkey), nil
}
