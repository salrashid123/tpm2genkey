package tpm2genkey

import (
	"bytes"
	"fmt"
	"io"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/salrashid123/tpm2genkey/util"
)

const ()

var ()

type PolicyJson struct {
	Policy []*TPMPolicyJson `json:"policy"`
}

type TPMPolicyJson struct {
	CommandCode   int    `json:"commandcode"`
	CommandPolicy []byte `json:"commandpolicy"`
}

type AuthPolicyJson struct {
	AuthPolicy []*TPMAuthPolicyJson `json:"authpolicy"`
}

type TPMAuthPolicyJson struct {
	Name   string           `json:"name"`
	Policy []*TPMPolicyJson `json:"policy"`
}

type NewKeyConfig struct {
	Debug              bool               // debug logging
	TPMDevice          io.ReadWriteCloser // initialized transport for the TPM
	Alg                string             // aes, rsa, ecdsa or hmac
	Exponent           int                // for rsa 65537
	Ownerpw            []byte
	Parentpw           []byte
	Parent             uint32 // Parent handle
	Password           []byte // auth password
	RSAKeySize         int    // for rsa 2048
	Curve              string // for ecdsa [secp224r1|prime256v1|secp384r1|secp521r1"
	Mode               string // for aes  [cfb|crt|ofb|cbc|ecb]
	AESKeySize         int    // for aes, 128
	PCRs               []uint // PCR banks to bind to
	Description        string
	EnablePolicySyntax bool // enable policy syntax https://www.hansenpartnership.com/draft-bottomley-tpm2-keys.html#section-4.1
}

func NewKey(h *NewKeyConfig) ([]byte, error) {

	// todo: validate input

	rwr := transport.FromReadWriter(h.TPMDevice)

	// setup the key template
	var keyTemplate tpm2.TPMTPublic

	sess, cleanup1, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16, []tpm2.AuthOption{tpm2.Trial(), tpm2.AESEncryption(128, tpm2.EncryptIn), tpm2.AESEncryption(128, tpm2.EncryptOut)}...)
	if err != nil {
		return nil, fmt.Errorf("setting up trial session: %v", err)
	}
	defer func() {
		if err := cleanup1(); err != nil {
			fmt.Printf("cleaning up trial session: %v", err)
		}
	}()

	var commandParameterPCR []byte
	var commandParameterAuth []byte
	if len(h.PCRs) > 0 {
		sel := tpm2.TPMLPCRSelection{
			PCRSelections: []tpm2.TPMSPCRSelection{
				{
					Hash:      tpm2.TPMAlgSHA256,
					PCRSelect: tpm2.PCClientCompatible.PCRs(h.PCRs...),
				},
			},
		}

		expectedDigest, err := getExpectedPCRDigest(rwr, sel, tpm2.TPMAlgSHA256)
		if err != nil {
			return nil, fmt.Errorf("ERROR:  could not get PolicySession: %v", err)
		}

		pol := tpm2.PolicyPCR{
			PolicySession: sess.Handle(),
			Pcrs: tpm2.TPMLPCRSelection{
				PCRSelections: sel.PCRSelections,
			},
			PcrDigest: tpm2.TPM2BDigest{
				Buffer: expectedDigest,
			},
		}

		_, err = pol.Execute(rwr)
		if err != nil {
			return nil, fmt.Errorf("error executing PolicyPCR: %v", err)
		}

		// 23.7 TPM2_PolicyPCR https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-3-Commands-01.38.pdf
		// pcrSelectionSegment := tpm2.Marshal(sel)
		// pcrDigestSegment := tpm2.Marshal(tpm2.TPM2BDigest{
		// 	Buffer: expectedDigest,
		// })
		// commandParameterPCR = append(pcrDigestSegment, pcrSelectionSegment...)

		commandParameterPCR, err = util.CPBytes(pol)
		if err != nil {
			return nil, fmt.Errorf("error getting policy command bytes: %v", err)
		}

	}
	if h.Password != nil {
		_, err = tpm2.PolicyAuthValue{
			PolicySession: sess.Handle(),
		}.Execute(rwr)
		if err != nil {
			return nil, fmt.Errorf("error executing PolicyAuthValue: %v", err)
		}
		commandParameterAuth, err = util.CPBytes(tpm2.PolicyAuthValue{PolicySession: sess.Handle()})
		if err != nil {
			return nil, fmt.Errorf("error getting policy command bytes: %v", err)
		}
	}

	pgd, err := tpm2.PolicyGetDigest{
		PolicySession: sess.Handle(),
	}.Execute(rwr)
	if err != nil {
		return nil, fmt.Errorf("error executing PolicyGetDigest: %v", err)
	}

	if h.Alg == "rsa" {
		keyTemplate = tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgRSA,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				SignEncrypt:         true,
				FixedTPM:            true,
				FixedParent:         true,
				SensitiveDataOrigin: true,
				UserWithAuth:        true,
			},
			AuthPolicy: tpm2.TPM2BDigest{
				Buffer: pgd.PolicyDigest.Buffer,
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
					KeyBits:  tpm2.TPMKeyBits(h.RSAKeySize),
					Exponent: uint32(h.Exponent),
				},
			),
		}
	} else if h.Alg == "ecdsa" {

		var crv tpm2.TPMECCCurve
		switch h.Curve {
		// case "prime192v1":  // not an armored key
		// 	crv = tpm2.TPMECCNistP192
		case "secp224r1":
			crv = tpm2.TPMECCNistP224
		case "prime256v1":
			crv = tpm2.TPMECCNistP256
		case "secp384r1":
			crv = tpm2.TPMECCNistP384
		case "secp521r1":
			crv = tpm2.TPMECCNistP521
		default:
			return nil, fmt.Errorf("tpm2-genkey: unsuported ecdsa curve: %s  must be one of [secp224r1|prime256v1|secp384r1|secp521r1]\n", h.Curve)
		}

		keyTemplate = tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgECC,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				SignEncrypt:         true,
				FixedTPM:            true,
				FixedParent:         true,
				SensitiveDataOrigin: true,
				UserWithAuth:        true,
			},
			AuthPolicy: tpm2.TPM2BDigest{
				Buffer: pgd.PolicyDigest.Buffer,
			},
			Parameters: tpm2.NewTPMUPublicParms(
				tpm2.TPMAlgECC,
				&tpm2.TPMSECCParms{
					CurveID: crv,
					Scheme: tpm2.TPMTECCScheme{
						Scheme: tpm2.TPMAlgECDSA,
						Details: tpm2.NewTPMUAsymScheme(
							tpm2.TPMAlgECDSA,
							&tpm2.TPMSSigSchemeECDSA{
								HashAlg: tpm2.TPMAlgSHA256,
							},
						),
					},
				},
			),
		}
	} else if h.Alg == "aes" {

		var mode tpm2.TPMAlgID
		switch h.Mode {
		// case "prime192v1":  // not an armored key
		// 	crv = tpm2.TPMECCNistP192
		case "cfb":
			mode = tpm2.TPMAlgCFB
		case "crt":
			mode = tpm2.TPMAlgCTR
		case "ofb":
			mode = tpm2.TPMAlgOFB
		case "cbc":
			mode = tpm2.TPMAlgCBC
		case "ecb":
			mode = tpm2.TPMAlgECB
		default:
			return nil, fmt.Errorf("tpm2-genkey: unsuported ecdsa curve: %s  must be one of [cfb|crt|ofb|cbc|ecb]\n", h.Mode)
		}

		keyTemplate = tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgSymCipher,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				FixedTPM:            true,
				FixedParent:         true,
				UserWithAuth:        true,
				SensitiveDataOrigin: true,
				Decrypt:             true,
				SignEncrypt:         true,
			},
			AuthPolicy: tpm2.TPM2BDigest{
				Buffer: pgd.PolicyDigest.Buffer,
			},
			Parameters: tpm2.NewTPMUPublicParms(
				tpm2.TPMAlgSymCipher,
				&tpm2.TPMSSymCipherParms{
					Sym: tpm2.TPMTSymDefObject{
						Algorithm: tpm2.TPMAlgAES,
						Mode:      tpm2.NewTPMUSymMode(tpm2.TPMAlgAES, mode),
						KeyBits: tpm2.NewTPMUSymKeyBits(
							tpm2.TPMAlgAES,
							tpm2.TPMKeyBits(h.AESKeySize),
						),
					},
				},
			),
		}

	} else if h.Alg == "hmac" {

		keyTemplate = tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgKeyedHash,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				FixedTPM:            true,
				FixedParent:         true,
				SensitiveDataOrigin: true,
				UserWithAuth:        true,
				SignEncrypt:         true,
			},
			AuthPolicy: tpm2.TPM2BDigest{
				Buffer: pgd.PolicyDigest.Buffer,
			},
			Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgKeyedHash,
				&tpm2.TPMSKeyedHashParms{
					Scheme: tpm2.TPMTKeyedHashScheme{
						Scheme: tpm2.TPMAlgHMAC,
						Details: tpm2.NewTPMUSchemeKeyedHash(tpm2.TPMAlgHMAC,
							&tpm2.TPMSSchemeHMAC{
								HashAlg: tpm2.TPMAlgSHA256,
							}),
					},
				}),
		}

	} else {
		return nil, fmt.Errorf("tpm2-genkey: unknown key algorithm")
	}

	// now create the key, if the parent is a permanent handle,
	//     use the default h2 tenplate as the primary key teplate and then a key under that primary key
	// if the parent is a persistent handle, create a key using that as the parent.

	var keyresponse *tpm2.CreateResponse
	if keyfile.IsMSO(tpm2.TPMHandle(h.Parent), keyfile.TPM_HT_PERMANENT) {
		primary, err := tpm2.CreatePrimary{
			PrimaryHandle: tpm2.AuthHandle{
				Handle: tpm2.TPMHandle(h.Parent),
				Auth:   tpm2.PasswordAuth(h.Ownerpw),
			},
			InPublic: tpm2.New2B(keyfile.ECCSRK_H2_Template),
			InSensitive: tpm2.TPM2BSensitiveCreate{
				Sensitive: &tpm2.TPMSSensitiveCreate{
					UserAuth: tpm2.TPM2BAuth{
						Buffer: h.Parentpw,
					},
				},
			},
		}.Execute(rwr)
		if err != nil {
			return nil, fmt.Errorf("tpm2-genkey: can't create primary: %v", err)
		}

		defer func() {
			flushContextCmd := tpm2.FlushContext{
				FlushHandle: primary.ObjectHandle,
			}
			_, _ = flushContextCmd.Execute(rwr)
		}()

		keyresponse, err = tpm2.Create{
			ParentHandle: tpm2.AuthHandle{
				Handle: primary.ObjectHandle,
				Name:   primary.Name,
				Auth:   tpm2.PasswordAuth(h.Parentpw),
			},
			InPublic: tpm2.New2B(keyTemplate),
			InSensitive: tpm2.TPM2BSensitiveCreate{
				Sensitive: &tpm2.TPMSSensitiveCreate{
					UserAuth: tpm2.TPM2BAuth{
						Buffer: h.Password,
					},
				},
			},
		}.Execute(rwr)
		if err != nil {
			return nil, fmt.Errorf("tpm2-genkey: can't create key: %v", err)
		}
	} else if keyfile.IsMSO(tpm2.TPMHandle(h.Parent), keyfile.TPM_HT_PERSISTENT) {

		p, err := tpm2.ReadPublic{
			ObjectHandle: tpm2.TPMHandle(h.Parent),
		}.Execute(rwr)
		if err != nil {
			return nil, fmt.Errorf("tpm2-genkey: can't read public: %v", err)
		}

		keyresponse, err = tpm2.Create{
			ParentHandle: tpm2.AuthHandle{
				Handle: tpm2.TPMHandle(h.Parent),
				Name:   p.Name,
				Auth:   tpm2.PasswordAuth(h.Parentpw),
			},
			InPublic: tpm2.New2B(keyTemplate),
			InSensitive: tpm2.TPM2BSensitiveCreate{
				Sensitive: &tpm2.TPMSSensitiveCreate{
					UserAuth: tpm2.TPM2BAuth{
						Buffer: h.Password,
					},
				},
			},
		}.Execute(rwr)
		if err != nil {
			return nil, fmt.Errorf("tpm2-genkey: can't create key: %v", err)
		}
	} else {
		return nil, fmt.Errorf("tpm2-genkey: unsupported parent handle %d\n", h.Parent)
	}

	// var authpol []*keyfile.TPMAuthPolicy
	// if len(h.PCRs) > 0 {
	// 	var pol []*keyfile.TPMPolicy
	// 	pol = append(pol, &keyfile.TPMPolicy{
	// 		CommandCode:   int(tpm2.TPMCCPolicyPCR),
	// 		CommandPolicy: pgd.PolicyDigest.Buffer,
	// 	})
	// 	authpol = append(authpol, &keyfile.TPMAuthPolicy{
	// 		Name:   h.AuthPolicyName,
	// 		Policy: pol,
	// 	})
	// }

	var pol []*keyfile.TPMPolicy
	if h.EnablePolicySyntax {
		if len(h.PCRs) > 0 {
			pol = append(pol, &keyfile.TPMPolicy{
				CommandCode:   int(tpm2.TPMCCPolicyPCR),
				CommandPolicy: commandParameterPCR,
			})
		}

		if len(h.Password) > 0 {
			pol = append(pol, &keyfile.TPMPolicy{
				CommandCode:   int(tpm2.TPMCCPolicyAuthValue),
				CommandPolicy: commandParameterAuth,
			})
		}
	}

	kf := keyfile.NewTPMKey(
		keyfile.OIDLoadableKey,
		keyresponse.OutPublic,
		keyresponse.OutPrivate,
		keyfile.WithParent(tpm2.TPMHandle(h.Parent)),
		keyfile.WithUserAuth(h.Password),
		keyfile.WithDescription(h.Description),
		keyfile.WithPolicy(pol),
	)

	keyFileBytes := new(bytes.Buffer)
	err = keyfile.Encode(keyFileBytes, kf)
	if err != nil {
		return nil, fmt.Errorf("tpm2-genkey: can't create key bytes: %v", err)
	}

	return keyFileBytes.Bytes(), nil
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
