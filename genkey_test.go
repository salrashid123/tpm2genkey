package tpm2genkey

import (
	"crypto"
	"crypto/aes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"testing"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/stretchr/testify/require"
)

const (
	maxInputBuffer = 1024
)

var ()

func TestGenKeyRSA(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	tests := []struct {
		name     string
		exponent int
		keysize  int
	}{
		{"keysize_1024", 65537, 1024},
		{"keysize_2048", 65537, 2048},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {

			k, err := NewKey(&NewKeyConfig{
				TPMDevice:  tpmDevice,
				Alg:        "rsa",
				Parent:     tpm2.TPMRHOwner.HandleValue(),
				Exponent:   tc.exponent,
				RSAKeySize: tc.keysize,
			})
			require.NoError(t, err)

			regenKey, err := keyfile.Decode(k)
			require.NoError(t, err)

			p, err := tpm2.Unmarshal[tpm2.TPMTPublic](regenKey.Pubkey.Bytes())
			require.NoError(t, err)

			require.Equal(t, p.Type, tpm2.TPMAlgRSA)

			rsad, err := p.Parameters.RSADetail()
			require.NoError(t, err)

			require.Equal(t, rsad.Exponent, uint32(tc.exponent))
			require.Equal(t, rsad.KeyBits, tpm2.TPMKeyBits(uint16(tc.keysize)))

			_, err = tpm2.Unmarshal[tpm2.TPM2BPrivate](regenKey.Privkey.Buffer)
			require.NoError(t, err)

			rwr := transport.FromReadWriter(tpmDevice)

			primary, err := tpm2.CreatePrimary{
				PrimaryHandle: tpm2.AuthHandle{
					Handle: tpm2.TPMRHOwner,
					Auth:   tpm2.PasswordAuth(nil),
				},
				InPublic: tpm2.New2B(keyfile.ECCSRK_H2_Template),
			}.Execute(rwr)
			require.NoError(t, err)
			defer func() {
				flushContextCmd := tpm2.FlushContext{
					FlushHandle: primary.ObjectHandle,
				}
				_, _ = flushContextCmd.Execute(rwr)
			}()

			rsaKeyResponse, err := tpm2.Load{
				ParentHandle: tpm2.NamedHandle{
					Handle: primary.ObjectHandle,
					Name:   primary.Name,
				},
				InPublic:  regenKey.Pubkey,
				InPrivate: regenKey.Privkey,
			}.Execute(rwr)
			require.NoError(t, err)

			data := []byte("stringtosign")

			digest := sha256.Sum256(data)

			rspSign, err := tpm2.Sign{
				KeyHandle: tpm2.AuthHandle{
					Handle: rsaKeyResponse.ObjectHandle,
					Name:   rsaKeyResponse.Name,
					Auth:   tpm2.PasswordAuth(nil),
				},
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
			require.NoError(t, err)

			pub, err := regenKey.Pubkey.Contents()
			require.NoError(t, err)

			rsaDetail, err := pub.Parameters.RSADetail()
			require.NoError(t, err)

			rsaUnique, err := pub.Unique.RSA()
			require.NoError(t, err)

			rsaPub, err := tpm2.RSAPub(rsaDetail, rsaUnique)
			require.NoError(t, err)

			rsassa, err := rspSign.Signature.Signature.RSASSA()
			require.NoError(t, err)

			err = rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, digest[:], rsassa.Sig.Buffer)
			require.NoError(t, err)
		})
	}
}

func TestGenKeyECDSA(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	tests := []struct {
		name  string
		curve tpm2.TPMECCCurve
	}{
		{"secp224r1", tpm2.TPMECCNistP224},
		{"prime256v1", tpm2.TPMECCNistP256},
		{"secp384r1", tpm2.TPMECCNistP384},
		{"secp521r1", tpm2.TPMECCNistP521},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {

			k, err := NewKey(&NewKeyConfig{
				TPMDevice: tpmDevice,
				Alg:       "ecdsa",
				Parent:    tpm2.TPMRHOwner.HandleValue(),
				Curve:     tc.name,
			})
			regenKey, err := keyfile.Decode(k)
			require.NoError(t, err)

			p, err := tpm2.Unmarshal[tpm2.TPMTPublic](regenKey.Pubkey.Bytes())
			require.NoError(t, err)

			require.Equal(t, p.Type, tpm2.TPMAlgECC)

			eccd, err := p.Parameters.ECCDetail()
			require.NoError(t, err)
			require.Equal(t, eccd.CurveID, tc.curve)

			_, err = tpm2.Unmarshal[tpm2.TPM2BPrivate](regenKey.Privkey.Buffer)
			require.NoError(t, err)
		})
	}
}

func TestGenKeyAuth(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	require.NoError(t, err)

	password := "foo"

	b, err := NewKey(&NewKeyConfig{
		TPMDevice:  tpmDevice,
		Alg:        "rsa",
		Parent:     tpm2.TPMRHOwner.HandleValue(),
		Password:   []byte(password),
		Exponent:   65537,
		RSAKeySize: 1024,
	})
	require.NoError(t, err)

	regenKey, err := keyfile.Decode(b)
	require.NoError(t, err)

	require.False(t, regenKey.EmptyAuth)

	rwr := transport.FromReadWriter(tpmDevice)

	primary, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.New2B(keyfile.ECCSRK_H2_Template),
	}.Execute(rwr)
	require.NoError(t, err)
	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: primary.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	rsaKeyResponse, err := tpm2.Load{
		ParentHandle: tpm2.NamedHandle{
			Handle: primary.ObjectHandle,
			Name:   primary.Name,
		},
		InPublic:  regenKey.Pubkey,
		InPrivate: regenKey.Privkey,
	}.Execute(rwr)
	require.NoError(t, err)

	data := []byte("stringtosign")

	digest := sha256.Sum256(data)

	rspSign, err := tpm2.Sign{
		KeyHandle: tpm2.AuthHandle{
			Handle: rsaKeyResponse.ObjectHandle,
			Name:   rsaKeyResponse.Name,
			Auth:   tpm2.PasswordAuth([]byte(password)),
		},
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
	require.NoError(t, err)

	pub, err := regenKey.Pubkey.Contents()
	require.NoError(t, err)

	rsaDetail, err := pub.Parameters.RSADetail()
	require.NoError(t, err)

	rsaUnique, err := pub.Unique.RSA()
	require.NoError(t, err)

	rsaPub, err := tpm2.RSAPub(rsaDetail, rsaUnique)
	require.NoError(t, err)

	rsassa, err := rspSign.Signature.Signature.RSASSA()
	require.NoError(t, err)

	err = rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, digest[:], rsassa.Sig.Buffer)
	require.NoError(t, err)
}

func TestGenKeyNoAuth(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	b, err := NewKey(&NewKeyConfig{
		TPMDevice: tpmDevice,
		Alg:       "ecdsa",
		Parent:    tpm2.TPMRHOwner.HandleValue(),
		Curve:     "prime256v1",
	})
	require.NoError(t, err)

	regenKey, err := keyfile.Decode(b)
	require.NoError(t, err)

	require.True(t, regenKey.EmptyAuth)
}

func TestGenKeyPCR(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	pcrs := []uint{0, 23}

	b, err := NewKey(&NewKeyConfig{
		TPMDevice:          tpmDevice,
		Alg:                "rsa",
		Parent:             tpm2.TPMRHOwner.HandleValue(),
		Exponent:           65537,
		RSAKeySize:         1024,
		PCRs:               pcrs,
		EnablePolicySyntax: true,
	})
	require.NoError(t, err)

	regenKey, err := keyfile.Decode(b)
	require.NoError(t, err)

	require.True(t, regenKey.EmptyAuth)

	require.Equal(t, 1, len(regenKey.Policy))

	rwr := transport.FromReadWriter(tpmDevice)

	primary, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.New2B(keyfile.ECCSRK_H2_Template),
	}.Execute(rwr)
	require.NoError(t, err)

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: primary.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	rsaKeyResponse, err := tpm2.Load{
		ParentHandle: tpm2.NamedHandle{
			Handle: primary.ObjectHandle,
			Name:   primary.Name,
		},
		InPublic:  regenKey.Pubkey,
		InPrivate: regenKey.Privkey,
	}.Execute(rwr)
	require.NoError(t, err)

	data := []byte("stringtosign")

	digest := sha256.Sum256(data)

	sess, cleanup1, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16, []tpm2.AuthOption{}...)
	require.NoError(t, err)

	defer cleanup1()

	ppol := regenKey.Policy[0]

	sel := tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{
			{
				Hash:      tpm2.TPMAlgSHA256,
				PCRSelect: tpm2.PCClientCompatible.PCRs(pcrs...),
			},
		},
	}

	expectedDigest, err := getExpectedPCRDigest(rwr, sel, tpm2.TPMAlgSHA256)
	require.NoError(t, err)

	// 23.7 TPM2_PolicyPCR https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-3-Commands-01.38.pdf
	pcrSelectionSegment := tpm2.Marshal(sel)
	pcrDigestSegment := tpm2.Marshal(tpm2.TPM2BDigest{
		Buffer: expectedDigest,
	})

	commandParameter := append(pcrDigestSegment, pcrSelectionSegment...)
	require.Equal(t, int(tpm2.TPMCCPolicyPCR), ppol.CommandCode)
	require.Equal(t, commandParameter, ppol.CommandPolicy)

	d, err := tpm2.Unmarshal[tpm2.TPM2BDigest](ppol.CommandPolicy)
	require.NoError(t, err)

	tc, err := tpm2.Unmarshal[tpm2.TPMLPCRSelection](ppol.CommandPolicy[len(d.Buffer)+2:]) // digest includes 2 byte size prefix
	require.NoError(t, err)

	_, err = tpm2.PolicyPCR{
		PolicySession: sess.Handle(),
		PcrDigest:     *d,
		Pcrs:          *tc,
	}.Execute(rwr)
	require.NoError(t, err)

	// _, err = tpm2.PolicyPCR{
	// 	PolicySession: sess.Handle(),
	// 	Pcrs: tpm2.TPMLPCRSelection{
	// 		PCRSelections: sel.PCRSelections,
	// 	},
	// }.Execute(rwr)
	// require.NoError(t, err)

	rspSign, err := tpm2.Sign{
		KeyHandle: tpm2.AuthHandle{
			Handle: rsaKeyResponse.ObjectHandle,
			Name:   rsaKeyResponse.Name,
			Auth:   sess,
		},
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
	require.NoError(t, err)

	pub, err := regenKey.Pubkey.Contents()
	require.NoError(t, err)

	rsaDetail, err := pub.Parameters.RSADetail()
	require.NoError(t, err)

	rsaUnique, err := pub.Unique.RSA()
	require.NoError(t, err)

	rsaPub, err := tpm2.RSAPub(rsaDetail, rsaUnique)
	require.NoError(t, err)

	rsassa, err := rspSign.Signature.Signature.RSASSA()
	require.NoError(t, err)

	err = rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, digest[:], rsassa.Sig.Buffer)
	require.NoError(t, err)
}

func TestGenKeyPCRPassword(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	password := "foo"

	pcrs := []uint{0, 23}

	b, err := NewKey(&NewKeyConfig{
		TPMDevice:          tpmDevice,
		Alg:                "rsa",
		Parent:             tpm2.TPMRHOwner.HandleValue(),
		Exponent:           65537,
		RSAKeySize:         1024,
		PCRs:               pcrs,
		Password:           []byte(password),
		EnablePolicySyntax: true,
	})
	require.NoError(t, err)

	regenKey, err := keyfile.Decode(b)
	require.NoError(t, err)

	require.False(t, regenKey.EmptyAuth)

	require.Equal(t, 2, len(regenKey.Policy))

	rwr := transport.FromReadWriter(tpmDevice)

	primary, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.New2B(keyfile.ECCSRK_H2_Template),
	}.Execute(rwr)
	require.NoError(t, err)

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: primary.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	rsaKeyResponse, err := tpm2.Load{
		ParentHandle: tpm2.NamedHandle{
			Handle: primary.ObjectHandle,
			Name:   primary.Name,
		},
		InPublic:  regenKey.Pubkey,
		InPrivate: regenKey.Privkey,
	}.Execute(rwr)
	require.NoError(t, err)

	data := []byte("stringtosign")

	digest := sha256.Sum256(data)

	sess, cleanup1, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16, []tpm2.AuthOption{tpm2.Auth([]byte(password))}...)
	require.NoError(t, err)

	defer cleanup1()

	for _, ppol := range regenKey.Policy {
		switch cc := ppol.CommandCode; cc {
		case int(tpm2.TPMCCPolicyPCR):
			sel := tpm2.TPMLPCRSelection{
				PCRSelections: []tpm2.TPMSPCRSelection{
					{
						Hash:      tpm2.TPMAlgSHA256,
						PCRSelect: tpm2.PCClientCompatible.PCRs(pcrs...),
					},
				},
			}

			expectedDigest, err := getExpectedPCRDigest(rwr, sel, tpm2.TPMAlgSHA256)
			require.NoError(t, err)

			// 23.7 TPM2_PolicyPCR https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-3-Commands-01.38.pdf
			pcrSelectionSegment := tpm2.Marshal(sel)
			pcrDigestSegment := tpm2.Marshal(tpm2.TPM2BDigest{
				Buffer: expectedDigest,
			})

			commandParameter := append(pcrDigestSegment, pcrSelectionSegment...)
			require.Equal(t, int(tpm2.TPMCCPolicyPCR), ppol.CommandCode)
			require.Equal(t, commandParameter, ppol.CommandPolicy)

			// TPM2BDigest struct section 10.4.2 https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf
			//    size UINT16
			//    buffer[size]{:sizeof(TPMU_HA)} BYTE

			// get the length of the digest, first 2bytes is length of buffer
			l := binary.BigEndian.Uint16(ppol.CommandPolicy[:2])
			dgst := ppol.CommandPolicy[:l+2]

			require.Equal(t, pcrDigestSegment, dgst)

			d, err := tpm2.Unmarshal[tpm2.TPM2BDigest](dgst)
			require.NoError(t, err)

			require.Equal(t, pcrSelectionSegment, ppol.CommandPolicy[l+2:])

			tc, err := tpm2.Unmarshal[tpm2.TPMLPCRSelection](ppol.CommandPolicy[l+2:]) // digest includes 2 byte size prefix
			require.NoError(t, err)

			_, err = tpm2.PolicyPCR{
				PolicySession: sess.Handle(),
				PcrDigest:     *d,
				Pcrs:          *tc,
			}.Execute(rwr)
			require.NoError(t, err)

		case int(tpm2.TPMCCPolicyAuthValue):
			_, err = tpm2.PolicyAuthValue{
				PolicySession: sess.Handle(),
			}.Execute(rwr)
			require.NoError(t, err)
		default:
			require.Fail(t, "Unsupported command parameter")
		}
	}

	rspSign, err := tpm2.Sign{
		KeyHandle: tpm2.AuthHandle{
			Handle: rsaKeyResponse.ObjectHandle,
			Name:   rsaKeyResponse.Name,
			Auth:   sess,
		},
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
	require.NoError(t, err)

	pub, err := regenKey.Pubkey.Contents()
	require.NoError(t, err)

	rsaDetail, err := pub.Parameters.RSADetail()
	require.NoError(t, err)

	rsaUnique, err := pub.Unique.RSA()
	require.NoError(t, err)

	rsaPub, err := tpm2.RSAPub(rsaDetail, rsaUnique)
	require.NoError(t, err)

	rsassa, err := rspSign.Signature.Signature.RSASSA()
	require.NoError(t, err)

	err = rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, digest[:], rsassa.Sig.Buffer)
	require.NoError(t, err)
}

func TestGenKeyPCRFail(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	require.NoError(t, err)

	pcrs := []uint{0, 23}

	b, err := NewKey(&NewKeyConfig{
		TPMDevice:  tpmDevice,
		Alg:        "rsa",
		Parent:     tpm2.TPMRHOwner.HandleValue(),
		Exponent:   65537,
		RSAKeySize: 1024,
		PCRs:       pcrs,
	})
	require.NoError(t, err)

	regenKey, err := keyfile.Decode(b)
	require.NoError(t, err)

	require.True(t, regenKey.EmptyAuth)

	rwr := transport.FromReadWriter(tpmDevice)

	primary, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.New2B(keyfile.ECCSRK_H2_Template),
	}.Execute(rwr)
	require.NoError(t, err)

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: primary.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	rsaKeyResponse, err := tpm2.Load{
		ParentHandle: tpm2.NamedHandle{
			Handle: primary.ObjectHandle,
			Name:   primary.Name,
		},
		InPublic:  regenKey.Pubkey,
		InPrivate: regenKey.Privkey,
	}.Execute(rwr)
	require.NoError(t, err)

	data := []byte("stringtosign")

	digest := sha256.Sum256(data)

	sess, cleanup1, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16, []tpm2.AuthOption{}...)
	require.NoError(t, err)

	defer cleanup1()

	sel := tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{
			{
				Hash:      tpm2.TPMAlgSHA256,
				PCRSelect: tpm2.PCClientCompatible.PCRs(pcrs...),
			},
		},
	}

	_, err = tpm2.PolicyPCR{
		PolicySession: sess.Handle(),
		Pcrs: tpm2.TPMLPCRSelection{
			PCRSelections: sel.PCRSelections,
		},
	}.Execute(rwr)
	require.NoError(t, err)

	pcrReadRsp, err := tpm2.PCRRead{
		PCRSelectionIn: tpm2.TPMLPCRSelection{
			PCRSelections: []tpm2.TPMSPCRSelection{
				{
					Hash:      tpm2.TPMAlgSHA256,
					PCRSelect: tpm2.PCClientCompatible.PCRs(pcrs...),
				},
			},
		},
	}.Execute(rwr)
	require.NoError(t, err)

	_, err = tpm2.PCRExtend{
		PCRHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMHandle(uint32(23)),
			Auth:   tpm2.PasswordAuth(nil),
		},
		Digests: tpm2.TPMLDigestValues{
			Digests: []tpm2.TPMTHA{
				{
					HashAlg: tpm2.TPMAlgSHA256,
					Digest:  pcrReadRsp.PCRValues.Digests[0].Buffer,
				},
			},
		},
	}.Execute(rwr)
	require.NoError(t, err)

	_, err = tpm2.Sign{
		KeyHandle: tpm2.AuthHandle{
			Handle: rsaKeyResponse.ObjectHandle,
			Name:   rsaKeyResponse.Name,
			Auth:   sess,
		},
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
	require.Error(t, err)

}

func TestGenKeyParent(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	rwr := transport.FromReadWriter(tpmDevice)

	primaryKey, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.RSASRKTemplate),
	}.Execute(rwr)
	require.NoError(t, err)

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: primaryKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	persistentHandle := 0x81010003

	_, err = tpm2.EvictControl{
		Auth: tpm2.TPMRHOwner,
		ObjectHandle: &tpm2.NamedHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
		},
		PersistentHandle: tpm2.TPMHandle(persistentHandle),
	}.Execute(rwr)
	require.NoError(t, err)

	b, err := NewKey(&NewKeyConfig{
		TPMDevice: tpmDevice,
		Alg:       "ecdsa",
		Parent:    tpm2.TPMHandle(persistentHandle).HandleValue(),
		Curve:     "prime256v1",
	})
	require.NoError(t, err)

	regenKey, err := keyfile.Decode(b)
	require.NoError(t, err)

	require.Equal(t, regenKey.Parent, tpm2.TPMHandle(persistentHandle))
}

func TestGenKeyParentAuth(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	rwr := transport.FromReadWriter(tpmDevice)

	parentPwd := "bar"

	primaryKey, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(tpm2.RSASRKTemplate),
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: []byte(parentPwd),
				},
			},
		},
	}.Execute(rwr)
	require.NoError(t, err)

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: primaryKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	persistentHandle := 0x81010003
	_, err = tpm2.EvictControl{
		Auth: tpm2.TPMRHOwner,
		ObjectHandle: &tpm2.NamedHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
		},
		PersistentHandle: tpm2.TPMHandle(persistentHandle),
	}.Execute(rwr)
	require.NoError(t, err)

	_, err = NewKey(&NewKeyConfig{
		TPMDevice: tpmDevice,
		Alg:       "ecdsa",
		Parent:    tpm2.TPMHandle(persistentHandle).HandleValue(),
		Curve:     "prime256v1",
		Parentpw:  []byte(parentPwd),
	})
	require.NoError(t, err)
}

func TestGenKeyOwnerAuth(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	rwr := transport.FromReadWriter(tpmDevice)

	ownerPwd := "bar"
	_, err = tpm2.HierarchyChangeAuth{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(nil),
		},
		NewAuth: tpm2.TPM2BAuth{
			Buffer: []byte(ownerPwd),
		},
	}.Execute(rwr)
	require.NoError(t, err)

	_, err = NewKey(&NewKeyConfig{
		TPMDevice: tpmDevice,
		Alg:       "ecdsa",
		Parent:    tpm2.TPMRHOwner.HandleValue(),
		Curve:     "prime256v1",
		Ownerpw:   []byte(ownerPwd),
	})
	require.NoError(t, err)
}

func TestGenKeyOwnerParentAuthPersistent(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	rwr := transport.FromReadWriter(tpmDevice)

	ownerPwd := "ownerpass"
	_, err = tpm2.HierarchyChangeAuth{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(nil),
		},
		NewAuth: tpm2.TPM2BAuth{
			Buffer: []byte(ownerPwd),
		},
	}.Execute(rwr)
	require.NoError(t, err)

	parentPwd := "parentpass"

	primaryKey, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth([]byte(ownerPwd)),
		},
		InPublic: tpm2.New2B(tpm2.RSASRKTemplate),
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				UserAuth: tpm2.TPM2BAuth{
					Buffer: []byte(parentPwd),
				},
			},
		},
	}.Execute(rwr)
	require.NoError(t, err)

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: primaryKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	persistentHandle := 0x81010003

	_, err = tpm2.EvictControl{
		Auth: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth([]byte(ownerPwd)),
		},
		ObjectHandle: &tpm2.NamedHandle{
			Handle: primaryKey.ObjectHandle,
			Name:   primaryKey.Name,
		},
		PersistentHandle: tpm2.TPMHandle(persistentHandle),
	}.Execute(rwr)
	require.NoError(t, err)

	_, err = NewKey(&NewKeyConfig{
		TPMDevice: tpmDevice,
		Alg:       "ecdsa",
		Parent:    tpm2.TPMHandle(persistentHandle).HandleValue(),
		Curve:     "prime256v1",
		Parentpw:  []byte(parentPwd),
	})
	require.NoError(t, err)
}

func TestGenKeyOwnerParentAuthPermanent(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	rwr := transport.FromReadWriter(tpmDevice)

	ownerPwd := "ownerpass"
	_, err = tpm2.HierarchyChangeAuth{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(nil),
		},
		NewAuth: tpm2.TPM2BAuth{
			Buffer: []byte(ownerPwd),
		},
	}.Execute(rwr)
	require.NoError(t, err)

	parentPwd := "parentpass"
	password := "keypass"
	_, err = NewKey(&NewKeyConfig{
		TPMDevice: tpmDevice,
		Alg:       "ecdsa",
		Parent:    tpm2.TPMRHOwner.HandleValue(),
		Curve:     "prime256v1",
		Parentpw:  []byte(parentPwd),
		Ownerpw:   []byte(ownerPwd),
		Password:  []byte(password),
	})
	require.NoError(t, err)
}

func TestGenKeyAES(t *testing.T) {

	evenBlock := make([]byte, 32)
	_, err := rand.Read(evenBlock)
	if err != nil {
		t.Errorf("%v", err)
	}

	oddBlock := make([]byte, 35)
	_, err = rand.Read(oddBlock)
	if err != nil {
		t.Errorf("%v", err)
	}

	tests := []struct {
		name          string
		dataToEncrypt []byte
		mode          string
		aesKeySize    int
	}{

		{"cbf_128_oddBlock", oddBlock, "cfb", 128},
		{"cbf_256_oddBlock", oddBlock, "cfb", 256},
		{"cbf_128_evenBlock", evenBlock, "cfb", 128},

		{"crt_128_oddBlock", oddBlock, "crt", 128},
		{"crt_256_oddBlock", oddBlock, "crt", 256},
		{"crt_128_evenBlock", evenBlock, "crt", 128},

		// todo, pkcs7 padding for cbc when blocks are not multiple
		//{"cbc_128_oddBlock", oddBlock, "cbc", 128},
		//{"cbc_256_oddBlock", oddBlock, "cbc", 256},
		{"cbc_128_evenBlock", evenBlock, "cbc", 128},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {

			tpmDevice, err := simulator.Get()
			require.NoError(t, err)
			defer tpmDevice.Close()

			b, err := NewKey(&NewKeyConfig{
				TPMDevice:  tpmDevice,
				Alg:        "aes",
				Parent:     tpm2.TPMRHOwner.HandleValue(),
				Password:   []byte(nil),
				Mode:       tc.mode,
				AESKeySize: tc.aesKeySize,
			})
			require.NoError(t, err)

			regenKey, err := keyfile.Decode(b)
			require.NoError(t, err)

			rwr := transport.FromReadWriter(tpmDevice)

			primary, err := tpm2.CreatePrimary{
				PrimaryHandle: tpm2.AuthHandle{
					Handle: tpm2.TPMRHOwner,
					Auth:   tpm2.PasswordAuth(nil),
				},
				InPublic: tpm2.New2B(keyfile.ECCSRK_H2_Template),
			}.Execute(rwr)
			require.NoError(t, err)
			defer func() {
				flushContextCmd := tpm2.FlushContext{
					FlushHandle: primary.ObjectHandle,
				}
				_, _ = flushContextCmd.Execute(rwr)
			}()

			aesKeyResponse, err := tpm2.Load{
				ParentHandle: tpm2.NamedHandle{
					Handle: primary.ObjectHandle,
					Name:   primary.Name,
				},
				InPublic:  regenKey.Pubkey,
				InPrivate: regenKey.Privkey,
			}.Execute(rwr)
			require.NoError(t, err)

			iv := make([]byte, aes.BlockSize)
			_, err = io.ReadFull(rand.Reader, iv)
			require.NoError(t, err)

			var mode tpm2.TPMAlgID
			switch tc.mode {
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
				t.Error(t, "unknown mode")
			}

			keyAuth := tpm2.AuthHandle{
				Handle: aesKeyResponse.ObjectHandle,
				Name:   aesKeyResponse.Name,
				Auth:   tpm2.PasswordAuth(nil),
			}

			// test encryption

			encrypted, err := encryptDecryptSymmetric(rwr, keyAuth, iv, tc.dataToEncrypt, mode, false)
			if err != nil {
				t.Errorf("%v", err)
			}

			decrypted, err := encryptDecryptSymmetric(rwr, keyAuth, iv, encrypted, mode, true)
			if err != nil {
				t.Errorf("%v", err)
			}

			require.Equal(t, tc.dataToEncrypt, decrypted)
		})
	}
}

const maxDigestBuffer = 1024

func encryptDecryptSymmetric(rwr transport.TPM, keyAuth tpm2.AuthHandle, iv, data []byte, mode tpm2.TPMAlgID, decrypt bool) ([]byte, error) {
	var out, block []byte

	for rest := data; len(rest) > 0; {
		if len(rest) > maxDigestBuffer {
			block, rest = rest[:maxDigestBuffer], rest[maxDigestBuffer:]
		} else {
			block, rest = rest, nil
		}
		r, err := tpm2.EncryptDecrypt2{
			KeyHandle: keyAuth,
			Message: tpm2.TPM2BMaxBuffer{
				Buffer: block,
			},
			Mode:    mode,
			Decrypt: decrypt,
			IV: tpm2.TPM2BIV{
				Buffer: iv,
			},
		}.Execute(rwr)
		if err != nil {
			return nil, err
		}
		block = r.OutData.Buffer
		iv = r.IV.Buffer

		out = append(out, block...)

	}
	return out, nil
}

func TestGenKeyHMAC(t *testing.T) {
	tpmDevice, err := simulator.Get()
	require.NoError(t, err)
	defer tpmDevice.Close()

	b, err := NewKey(&NewKeyConfig{
		TPMDevice: tpmDevice,
		Alg:       "hmac",
		Parent:    tpm2.TPMRHOwner.HandleValue(),
	})
	require.NoError(t, err)

	regenKey, err := keyfile.Decode(b)
	require.NoError(t, err)

	rwr := transport.FromReadWriter(tpmDevice)

	primary, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHOwner,
			Auth:   tpm2.PasswordAuth(nil),
		},
		InPublic: tpm2.New2B(keyfile.ECCSRK_H2_Template),
	}.Execute(rwr)
	require.NoError(t, err)
	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: primary.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()

	hmacKey, err := tpm2.Load{
		ParentHandle: tpm2.NamedHandle{
			Handle: primary.ObjectHandle,
			Name:   primary.Name,
		},
		InPublic:  regenKey.Pubkey,
		InPrivate: regenKey.Privkey,
	}.Execute(rwr)
	require.NoError(t, err)

	data := []byte("string to mac")

	objAuth := &tpm2.TPM2BAuth{}
	_, err = hmac(rwr, data, hmacKey.ObjectHandle, hmacKey.Name, *objAuth)
	require.NoError(t, err)

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: hmacKey.ObjectHandle,
		}
		_, _ = flushContextCmd.Execute(rwr)
	}()
}

func hmac(rwr transport.TPM, data []byte, objHandle tpm2.TPMHandle, objName tpm2.TPM2BName, objAuth tpm2.TPM2BAuth) ([]byte, error) {

	sas, sasCloser, err := tpm2.HMACSession(rwr, tpm2.TPMAlgSHA256, 16, tpm2.Auth(objAuth.Buffer))
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = sasCloser()
	}()

	defer func() {
		flushContextCmd := tpm2.FlushContext{
			FlushHandle: sas.Handle(),
		}
		_, err = flushContextCmd.Execute(rwr)
	}()

	hmacStart := tpm2.HmacStart{
		Handle: tpm2.AuthHandle{
			Handle: objHandle,
			Name:   objName,
			Auth:   sas,
		},
		Auth:    objAuth,
		HashAlg: tpm2.TPMAlgNull,
	}

	rspHS, err := hmacStart.Execute(rwr)
	if err != nil {
		return nil, err
	}

	authHandle := tpm2.AuthHandle{
		Name:   objName,
		Handle: rspHS.SequenceHandle,
		Auth:   tpm2.PasswordAuth(objAuth.Buffer),
	}
	for len(data) > maxInputBuffer {
		sequenceUpdate := tpm2.SequenceUpdate{
			SequenceHandle: authHandle,
			Buffer: tpm2.TPM2BMaxBuffer{
				Buffer: data[:maxInputBuffer],
			},
		}
		_, err = sequenceUpdate.Execute(rwr)
		if err != nil {
			return nil, err
		}

		data = data[maxInputBuffer:]
	}

	sequenceComplete := tpm2.SequenceComplete{
		SequenceHandle: authHandle,
		Buffer: tpm2.TPM2BMaxBuffer{
			Buffer: data,
		},
		Hierarchy: tpm2.TPMRHOwner,
	}

	rspSC, err := sequenceComplete.Execute(rwr)
	if err != nil {
		return nil, err
	}

	return rspSC.Result.Buffer, nil

}
