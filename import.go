package tpm2genkey

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/salrashid123/tpm2genkey/util"
)

const ()

var ()

type NewImportConfig struct {
	Debug              bool               // debug logging
	TPMDevice          io.ReadWriteCloser // initialized transport for the TPM
	Alg                string             // aes, rsa, ecdsa or hmac
	Exponent           int                // for rsa 65537
	RawKey             []byte             // the raw key to import (PEM format for RSA|ECC; rawbytes for AES|HMAC)
	Ownerpw            []byte             // root hierarchy password
	Parentpw           []byte             // password for parent key
	Parent             uint32             // Parent handle
	Password           []byte             // key auth password
	RSAScheme          tpm2.TPMTRSAScheme
	ECCCurve           tpm2.TPMECCCurve // for ecdsa [secp224r1|prime256v1|secp384r1|secp521r1"
	HashAlg            tpm2.TPMIAlgHash
	AESAlg             tpm2.TPMAlgID // for aes  [cfb|crt|ofb|cbc|ecb]
	AESKeySize         int           // for aes, 128
	PCRs               []uint        // PCR banks to bind to
	Description        string
	PersistentHandle   int  // persistentHandle to save the key in
	EnablePolicySyntax bool // enable policy syntax https://www.hansenpartnership.com/draft-bottomley-tpm2-keys.html#section-4.1
}

func NewImportKey(h *NewImportConfig) ([]byte, error) {

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

	if h.Parent == 0 {
		h.Parent = tpm2.TPMRHOwner.HandleValue()
	}

	if h.HashAlg == 0 {
		h.HashAlg = tpm2.TPMAlgSHA256
	}

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
	if len(h.Password) > 0 {
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

	var sens2B []byte

	switch h.Alg {
	case "rsa":

		block, _ := pem.Decode(h.RawKey)
		if block == nil {
			return nil, fmt.Errorf("tpm2-genkey:      Failed to decode PEM block containing the key %v", err)
		}
		pvp, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("tpm2-genkey:      Failed to parse PEM block containing the key %v", err)
		}

		pv, ok := pvp.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("tpm2-genkey:      Failed to covert PEM key to RSA private key %v", err)
		}

		keyTemplate = tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgRSA,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				FixedTPM:            false,
				FixedParent:         false,
				SensitiveDataOrigin: false,
				UserWithAuth:        true,
				SignEncrypt:         true,
			},
			AuthPolicy: pgd.PolicyDigest,
			Parameters: tpm2.NewTPMUPublicParms(
				tpm2.TPMAlgRSA,
				&tpm2.TPMSRSAParms{
					Exponent: uint32(pv.PublicKey.E),
					Scheme:   h.RSAScheme,
					KeyBits:  tpm2.TPMIRSAKeyBits(pv.N.BitLen()), // 2048,
				},
			),

			Unique: tpm2.NewTPMUPublicID(
				tpm2.TPMAlgRSA,
				&tpm2.TPM2BPublicKeyRSA{
					Buffer: pv.PublicKey.N.Bytes(),
				},
			),
		}

		sens2B = tpm2.Marshal(tpm2.TPMTSensitive{
			AuthValue: tpm2.TPM2BAuth{
				Buffer: h.Password,
			},
			SensitiveType: tpm2.TPMAlgRSA,
			Sensitive: tpm2.NewTPMUSensitiveComposite(
				tpm2.TPMAlgRSA,
				&tpm2.TPM2BPrivateKeyRSA{Buffer: pv.Primes[0].Bytes()},
			),
		})

	case "ecdsa":

		block, _ := pem.Decode(h.RawKey)
		if block == nil {
			return nil, fmt.Errorf("tpm2-genkey:      Failed to decode PEM block containing the key %v", err)
		}
		pvp, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("tpm2-genkey:      Failed to parse PEM block containing the key %v", err)
		}

		k := pvp.(*ecdsa.PrivateKey)

		pk := k.PublicKey

		keyTemplate = tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgECC,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				FixedTPM:            false,
				FixedParent:         false,
				SensitiveDataOrigin: false,
				UserWithAuth:        true,
				SignEncrypt:         true,
			},
			AuthPolicy: tpm2.TPM2BDigest{
				Buffer: pgd.PolicyDigest.Buffer,
			},
			Parameters: tpm2.NewTPMUPublicParms(
				tpm2.TPMAlgECC,
				&tpm2.TPMSECCParms{
					CurveID: h.ECCCurve,
					Scheme: tpm2.TPMTECCScheme{
						Scheme: tpm2.TPMAlgECDSA,
						Details: tpm2.NewTPMUAsymScheme(
							tpm2.TPMAlgECDSA,
							&tpm2.TPMSSigSchemeECDSA{
								HashAlg: h.HashAlg,
							},
						),
					},
				},
			),
			Unique: tpm2.NewTPMUPublicID(
				tpm2.TPMAlgECC,
				&tpm2.TPMSECCPoint{
					X: tpm2.TPM2BECCParameter{
						Buffer: pk.X.FillBytes(make([]byte, len(pk.X.Bytes()))), //pk.X.Bytes(), // pk.X.FillBytes(make([]byte, len(pk.X.Bytes()))),
					},
					Y: tpm2.TPM2BECCParameter{
						Buffer: pk.Y.FillBytes(make([]byte, len(pk.Y.Bytes()))), //pk.Y.Bytes(), // pk.Y.FillBytes(make([]byte, len(pk.Y.Bytes()))),
					},
				},
			),
		}

		sens2B = tpm2.Marshal(tpm2.TPMTSensitive{
			AuthValue: tpm2.TPM2BAuth{
				Buffer: h.Password,
			},
			SensitiveType: tpm2.TPMAlgECC,
			Sensitive: tpm2.NewTPMUSensitiveComposite(
				tpm2.TPMAlgECC,
				&tpm2.TPM2BECCParameter{Buffer: k.D.FillBytes(make([]byte, len(k.D.Bytes())))},
			),
		})

	case "aes":

		sv := make([]byte, 32)
		io.ReadFull(rand.Reader, sv)
		privHash := crypto.SHA256.New()
		privHash.Write(sv)
		privHash.Write(h.RawKey)

		keyTemplate = tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgSymCipher,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				FixedTPM:            false,
				FixedParent:         false,
				SensitiveDataOrigin: false,
				UserWithAuth:        true,
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
						Mode:      tpm2.NewTPMUSymMode(tpm2.TPMAlgAES, h.AESAlg),
						KeyBits: tpm2.NewTPMUSymKeyBits(
							tpm2.TPMAlgAES,
							tpm2.TPMKeyBits(h.AESKeySize),
						),
					},
				},
			),
			Unique: tpm2.NewTPMUPublicID(
				tpm2.TPMAlgSymCipher,
				&tpm2.TPM2BDigest{
					Buffer: privHash.Sum(nil),
				},
			),
		}

		sens := tpm2.TPMTSensitive{
			AuthValue: tpm2.TPM2BAuth{
				Buffer: h.Password,
			},
			SensitiveType: tpm2.TPMAlgSymCipher,
			SeedValue: tpm2.TPM2BDigest{
				Buffer: sv,
			},
			Sensitive: tpm2.NewTPMUSensitiveComposite(
				tpm2.TPMAlgSymCipher,
				&tpm2.TPM2BSymKey{Buffer: h.RawKey},
			),
		}

		if len(h.Password) > 0 {
			sens.AuthValue = tpm2.TPM2BAuth{
				Buffer: []byte(h.Password), // set any userAuth
			}
		}
		sens2B = tpm2.Marshal(sens)

	case "hmac":
		sv := make([]byte, 32)
		io.ReadFull(rand.Reader, sv)
		privHash := crypto.SHA256.New()
		privHash.Write(sv)
		privHash.Write(h.RawKey)

		keyTemplate = tpm2.TPMTPublic{
			Type:    tpm2.TPMAlgKeyedHash,
			NameAlg: tpm2.TPMAlgSHA256,
			ObjectAttributes: tpm2.TPMAObject{
				FixedTPM:            false,
				FixedParent:         false,
				SensitiveDataOrigin: false,
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
								HashAlg: h.HashAlg,
							}),
					},
				}),
			Unique: tpm2.NewTPMUPublicID(
				tpm2.TPMAlgKeyedHash,
				&tpm2.TPM2BDigest{
					Buffer: privHash.Sum(nil),
				},
			),
		}

		sens2B = tpm2.Marshal(tpm2.TPMTSensitive{
			SensitiveType: tpm2.TPMAlgKeyedHash,
			AuthValue: tpm2.TPM2BAuth{
				Buffer: h.Password,
			},
			SeedValue: tpm2.TPM2BDigest{
				Buffer: sv,
			},
			Sensitive: tpm2.NewTPMUSensitiveComposite(
				tpm2.TPMAlgKeyedHash,
				&tpm2.TPM2BSensitiveData{Buffer: h.RawKey},
			),
		})

	default:
		return nil, fmt.Errorf("tpm2-genkey: unknown key algorithm")
	}

	// now create the key, if the parent is a permanent handle,
	//     use the default h2 tenplate as the primary key teplate and then a key under that primary key
	// if the parent is a persistent handle, create a key using that as the parent.

	var keyresponse *tpm2.ImportResponse
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

		keyresponse, err = tpm2.Import{
			ParentHandle: tpm2.AuthHandle{
				Handle: primary.ObjectHandle,
				Name:   primary.Name,
				Auth:   tpm2.PasswordAuth(h.Parentpw),
			},
			ObjectPublic: tpm2.New2B(keyTemplate),
			Duplicate:    tpm2.TPM2BPrivate{Buffer: tpm2.Marshal(tpm2.TPM2BPrivate{Buffer: sens2B})},
		}.Execute(rwr)
		if err != nil {
			return nil, fmt.Errorf("tpm2-genkey: can't import key: %v", err)
		}

		if h.PersistentHandle != 0 {
			loadresponse, err := tpm2.Load{
				ParentHandle: tpm2.AuthHandle{
					Handle: primary.ObjectHandle,
					Name:   primary.Name,
					Auth:   tpm2.PasswordAuth(h.Parentpw),
				},
				InPrivate: keyresponse.OutPrivate,
				InPublic:  tpm2.New2B(keyTemplate),
			}.Execute(rwr)
			if err != nil {
				return nil, fmt.Errorf("tpm2-genkey: can't load key to persist : %v", err)
			}

			defer func() {
				flushContextCmd := tpm2.FlushContext{
					FlushHandle: loadresponse.ObjectHandle,
				}
				_, err = flushContextCmd.Execute(rwr)
			}()
			_, err = tpm2.EvictControl{
				Auth: tpm2.TPMRHOwner,
				ObjectHandle: &tpm2.NamedHandle{
					Handle: loadresponse.ObjectHandle,
					Name:   loadresponse.Name,
				},
				PersistentHandle: tpm2.TPMIDHPersistent(h.PersistentHandle),
			}.Execute(rwr)
			if err != nil {
				return nil, fmt.Errorf("tpm2-genkey: can't persist key: %v", err)
			}
		}
	} else if keyfile.IsMSO(tpm2.TPMHandle(h.Parent), keyfile.TPM_HT_PERSISTENT) {

		p, err := tpm2.ReadPublic{
			ObjectHandle: tpm2.TPMHandle(h.Parent),
		}.Execute(rwr)
		if err != nil {
			return nil, fmt.Errorf("tpm2-genkey: can't read public: %v", err)
		}

		keyresponse, err = tpm2.Import{
			ParentHandle: tpm2.AuthHandle{
				Handle: tpm2.TPMHandle(h.Parent),
				Name:   p.Name,
				Auth:   tpm2.PasswordAuth(h.Parentpw),
			},
			ObjectPublic: tpm2.New2B(keyTemplate),
			Duplicate:    tpm2.TPM2BPrivate{Buffer: tpm2.Marshal(tpm2.TPM2BPrivate{Buffer: sens2B})},
		}.Execute(rwr)
		if err != nil {
			return nil, fmt.Errorf("tpm2-genkey: can't import key: %v", err)
		}

		if h.PersistentHandle != 0 {
			loadresponse, err := tpm2.Load{
				ParentHandle: tpm2.AuthHandle{
					Handle: tpm2.TPMHandle(h.Parent),
					Name:   p.Name,
					Auth:   tpm2.PasswordAuth(h.Parentpw),
				},
				InPrivate: keyresponse.OutPrivate,
				InPublic:  tpm2.New2B(keyTemplate),
			}.Execute(rwr)
			if err != nil {
				return nil, fmt.Errorf("tpm2-genkey: can't load key to persist : %v", err)
			}

			defer func() {
				flushContextCmd := tpm2.FlushContext{
					FlushHandle: loadresponse.ObjectHandle,
				}
				_, err = flushContextCmd.Execute(rwr)
			}()
			_, err = tpm2.EvictControl{
				Auth: tpm2.TPMRHOwner,
				ObjectHandle: &tpm2.NamedHandle{
					Handle: loadresponse.ObjectHandle,
					Name:   loadresponse.Name,
				},
				PersistentHandle: tpm2.TPMIDHPersistent(h.PersistentHandle),
			}.Execute(rwr)
			if err != nil {
				return nil, fmt.Errorf("tpm2-genkey: can't persist key: %v", err)
			}
		}
	} else {
		return nil, fmt.Errorf("tpm2-genkey: unsupported parent handle %d", h.Parent)
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
		tpm2.New2B(keyTemplate),
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
