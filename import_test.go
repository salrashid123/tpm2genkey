package tpm2genkey

import (
	"crypto"
	"crypto/aes"
	"crypto/ecdsa"
	"crypto/elliptic"
	stdhmac "crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"testing"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/stretchr/testify/require"
)

const ()

var ()

func TestImportRSA(t *testing.T) {
	tpmDevice, err := net.Dial("tcp", swTPMPath)
	require.NoError(t, err)
	defer tpmDevice.Close()

	tests := []struct {
		name       string
		exponent   int
		keysize    int
		rsaScheme  string
		hashScheme string
	}{
		{"rsassa_1024_sha256", 65537, 1024, "rsassa", "sha256"},
		{"rsassa_2048_sha256", 65537, 2048, "rsassa", "sha256"},
		{"rsassa_2048_sha512", 65537, 2048, "rsassa", "sha512"},
		{"rsapss_2048_sha256", 65537, 2048, "rsapss", "sha256"},
		{"rsapss_2048_sha512", 65537, 2048, "rsapss", "sha512"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {

			privateKey, err := rsa.GenerateKey(rand.Reader, tc.keysize)
			require.NoError(t, err)

			derBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
			require.NoError(t, err)

			block := &pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: derBytes,
			}

			ppem := pem.EncodeToMemory(block)

			var hsh tpm2.TPMAlgID
			switch tc.hashScheme {
			case "sha256":
				hsh = tpm2.TPMAlgSHA256
			case "sha384":
				hsh = tpm2.TPMAlgSHA384
			case "sha512":
				hsh = tpm2.TPMAlgSHA512
			default:
				require.Error(t, fmt.Errorf("unknown hash %s", tc.hashScheme))
			}

			var sch tpm2.TPMTRSAScheme
			switch tc.rsaScheme {
			case "rsassa":
				sch = tpm2.TPMTRSAScheme{
					Scheme: tpm2.TPMAlgRSASSA,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgRSASSA,
						&tpm2.TPMSSigSchemeRSASSA{
							HashAlg: hsh,
						},
					),
				}
			case "rsapss":
				sch = tpm2.TPMTRSAScheme{
					Scheme: tpm2.TPMAlgRSAPSS,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgRSAPSS,
						&tpm2.TPMSSigSchemeRSAPSS{
							HashAlg: hsh,
						},
					),
				}
			default:
				require.Error(t, fmt.Errorf("unknown scheme %s", tc.rsaScheme))
			}

			k, err := NewImportKey(&NewImportConfig{
				TPMDevice: tpmDevice,
				Alg:       "rsa",
				RawKey:    ppem,
				Exponent:  tc.exponent,
				RSAScheme: sch,
				Parent:    tpm2.TPMRHOwner.HandleValue(),
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
			defer func() {
				flushContextCmd := tpm2.FlushContext{
					FlushHandle: rsaKeyResponse.ObjectHandle,
				}
				_, _ = flushContextCmd.Execute(rwr)
			}()

			data := []byte("stringtosign")

			var digest []byte
			var h crypto.Hash

			switch tc.hashScheme {
			case "sha256":
				h = crypto.SHA256
				d := sha256.Sum256(data)
				digest = d[:]
			case "sha512":
				h = crypto.SHA512
				d := sha512.Sum512(data)
				digest = d[:]
			default:
				require.Error(t, fmt.Errorf("unknown hash %s", tc.hashScheme))
			}

			switch tc.rsaScheme {
			case "rsassa":
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
								HashAlg: hsh,
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

				err = rsa.VerifyPKCS1v15(rsaPub, h, digest[:], rsassa.Sig.Buffer)
				require.NoError(t, err)
			case "rsapss":
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
						Scheme: tpm2.TPMAlgRSAPSS,
						Details: tpm2.NewTPMUSigScheme(
							tpm2.TPMAlgRSAPSS,
							&tpm2.TPMSSchemeHash{
								HashAlg: hsh,
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

				rsapss, err := rspSign.Signature.Signature.RSAPSS()
				require.NoError(t, err)

				err = rsa.VerifyPSS(rsaPub, h, digest[:], rsapss.Sig.Buffer, &rsa.PSSOptions{
					SaltLength: rsa.PSSSaltLengthAuto,
				})
				require.NoError(t, err)
			default:
				require.Error(t, fmt.Errorf("unknown scheme %s", tc.rsaScheme))
			}

		})
	}
}

func TestImportPassword(t *testing.T) {
	tpmDevice, err := net.Dial("tcp", swTPMPath)
	require.NoError(t, err)
	defer tpmDevice.Close()

	tests := []struct {
		name     string
		exponent int
		keysize  int
		password string
	}{
		{"keysize_2048", 65537, 2048, "foo"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {

			privateKey, err := rsa.GenerateKey(rand.Reader, tc.keysize)
			require.NoError(t, err)

			derBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
			require.NoError(t, err)

			block := &pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: derBytes,
			}

			ppem := pem.EncodeToMemory(block)

			sch := tpm2.TPMTRSAScheme{
				Scheme: tpm2.TPMAlgRSASSA,
				Details: tpm2.NewTPMUAsymScheme(
					tpm2.TPMAlgRSASSA,
					&tpm2.TPMSSigSchemeRSASSA{
						HashAlg: tpm2.TPMAlgSHA256,
					},
				),
			}

			k, err := NewImportKey(&NewImportConfig{
				TPMDevice: tpmDevice,
				Alg:       "rsa",
				RawKey:    ppem,
				Exponent:  tc.exponent,
				HashAlg:   tpm2.TPMAlgSHA256,
				RSAScheme: sch,
				Password:  []byte(tc.password),
				Parent:    tpm2.TPMRHOwner.HandleValue(),
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
			defer func() {
				flushContextCmd := tpm2.FlushContext{
					FlushHandle: rsaKeyResponse.ObjectHandle,
				}
				_, _ = flushContextCmd.Execute(rwr)
			}()

			data := []byte("stringtosign")

			digest := sha256.Sum256(data)

			rspSign, err := tpm2.Sign{
				KeyHandle: tpm2.AuthHandle{
					Handle: rsaKeyResponse.ObjectHandle,
					Name:   rsaKeyResponse.Name,
					Auth:   tpm2.PasswordAuth([]byte(tc.password)),
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

func TestImportPolicyAuthValue(t *testing.T) {
	tpmDevice, err := net.Dial("tcp", swTPMPath)
	require.NoError(t, err)
	defer tpmDevice.Close()

	tests := []struct {
		name     string
		exponent int
		keysize  int
		password string
	}{
		{"keysize_2048", 65537, 2048, "foo"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {

			privateKey, err := rsa.GenerateKey(rand.Reader, tc.keysize)
			require.NoError(t, err)

			derBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
			require.NoError(t, err)

			block := &pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: derBytes,
			}

			ppem := pem.EncodeToMemory(block)

			sch := tpm2.TPMTRSAScheme{
				Scheme: tpm2.TPMAlgRSASSA,
				Details: tpm2.NewTPMUAsymScheme(
					tpm2.TPMAlgRSASSA,
					&tpm2.TPMSSigSchemeRSASSA{
						HashAlg: tpm2.TPMAlgSHA256,
					},
				),
			}

			k, err := NewImportKey(&NewImportConfig{
				TPMDevice: tpmDevice,
				Alg:       "rsa",
				RawKey:    ppem,
				Exponent:  tc.exponent,
				HashAlg:   tpm2.TPMAlgSHA256,
				RSAScheme: sch,
				Password:  []byte(tc.password),
				Parent:    tpm2.TPMRHOwner.HandleValue(),
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
			defer func() {
				flushContextCmd := tpm2.FlushContext{
					FlushHandle: rsaKeyResponse.ObjectHandle,
				}
				_, _ = flushContextCmd.Execute(rwr)
			}()

			data := []byte("stringtosign")

			sess, cleanup, err := tpm2.PolicySession(rwr, tpm2.TPMAlgSHA256, 16, []tpm2.AuthOption{tpm2.Auth([]byte(tc.password))}...)
			require.NoError(t, err)
			defer cleanup()

			_, err = tpm2.PolicyAuthValue{
				PolicySession: sess.Handle(),
			}.Execute(rwr)
			require.NoError(t, err)

			digest := sha256.Sum256(data)

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

		})
	}
}

func TestImportECC(t *testing.T) {
	tpmDevice, err := net.Dial("tcp", swTPMPath)
	require.NoError(t, err)
	defer tpmDevice.Close()

	tests := []struct {
		name       string
		crv        elliptic.Curve
		hashScheme string
	}{
		{"ecc_p256_sha256", elliptic.P256(), "sha256"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {

			privateKey, err := ecdsa.GenerateKey(tc.crv, rand.Reader)
			require.NoError(t, err)

			derBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
			require.NoError(t, err)

			block := &pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: derBytes,
			}

			ppem := pem.EncodeToMemory(block)

			var hsh tpm2.TPMAlgID
			switch tc.hashScheme {
			case "sha256":
				hsh = tpm2.TPMAlgSHA256
			case "sha384":
				hsh = tpm2.TPMAlgSHA384
			case "sha512":
				hsh = tpm2.TPMAlgSHA512
			default:
				require.Error(t, fmt.Errorf("unknown hash %s", tc.hashScheme))
			}

			var tcrv tpm2.TPMECCCurve
			switch tc.crv {
			case elliptic.P256():
				tcrv = tpm2.TPMECCNistP256
			default:
				require.Error(t, fmt.Errorf("unknown hash %s", tc.hashScheme))
			}

			k, err := NewImportKey(&NewImportConfig{
				TPMDevice: tpmDevice,
				Alg:       "ecdsa",
				RawKey:    ppem,
				HashAlg:   hsh,
				ECCCurve:  tcrv,
				Parent:    tpm2.TPMRHOwner.HandleValue(),
			})
			require.NoError(t, err)

			regenKey, err := keyfile.Decode(k)
			require.NoError(t, err)

			p, err := tpm2.Unmarshal[tpm2.TPMTPublic](regenKey.Pubkey.Bytes())
			require.NoError(t, err)

			require.Equal(t, p.Type, tpm2.TPMAlgECC)

			rsad, err := p.Parameters.ECCDetail()
			require.NoError(t, err)

			require.Equal(t, rsad.CurveID, tcrv)

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

			eccKeyResponse, err := tpm2.Load{
				ParentHandle: tpm2.NamedHandle{
					Handle: primary.ObjectHandle,
					Name:   primary.Name,
				},
				InPublic:  regenKey.Pubkey,
				InPrivate: regenKey.Privkey,
			}.Execute(rwr)
			require.NoError(t, err)
			defer func() {
				flushContextCmd := tpm2.FlushContext{
					FlushHandle: eccKeyResponse.ObjectHandle,
				}
				_, _ = flushContextCmd.Execute(rwr)
			}()

			data := []byte("stringtosign")

			var digest []byte

			switch tc.hashScheme {
			case "sha256":
				d := sha256.Sum256(data)
				digest = d[:]
			case "sha512":

				d := sha512.Sum512(data)
				digest = d[:]
			default:
				require.Error(t, fmt.Errorf("unknown hash %s", tc.hashScheme))
			}

			eccSign, err := tpm2.Sign{
				KeyHandle: tpm2.AuthHandle{
					Handle: eccKeyResponse.ObjectHandle,
					Name:   eccKeyResponse.Name,
					Auth:   tpm2.PasswordAuth(nil),
				},
				Digest: tpm2.TPM2BDigest{
					Buffer: digest[:],
				},
				InScheme: tpm2.TPMTSigScheme{
					Scheme: tpm2.TPMAlgECDSA,
					Details: tpm2.NewTPMUSigScheme(
						tpm2.TPMAlgECDSA,
						&tpm2.TPMSSchemeHash{
							HashAlg: hsh,
						},
					),
				},
				Validation: tpm2.TPMTTKHashCheck{
					Tag: tpm2.TPMSTHashCheck,
				},
			}.Execute(rwr)
			require.NoError(t, err)

			ecs, err := eccSign.Signature.Signature.ECDSA()
			require.NoError(t, err)

			ecDetail, err := p.Parameters.ECCDetail()
			require.NoError(t, err)
			crv, err := ecDetail.CurveID.Curve()
			require.NoError(t, err)
			eccUnique, err := p.Unique.ECC()
			require.NoError(t, err)

			pubKey := &ecdsa.PublicKey{
				Curve: crv,
				X:     big.NewInt(0).SetBytes(eccUnique.X.Buffer),
				Y:     big.NewInt(0).SetBytes(eccUnique.Y.Buffer),
			}

			x := big.NewInt(0).SetBytes(ecs.SignatureR.Buffer)
			y := big.NewInt(0).SetBytes(ecs.SignatureS.Buffer)

			ok := ecdsa.Verify(pubKey, digest[:], x, y)
			require.True(t, ok, "Error verifying ecc signature")

		})
	}
}

func TestImportAES(t *testing.T) {

	tpmDevice, err := net.Dial("tcp", swTPMPath)
	require.NoError(t, err)
	defer tpmDevice.Close()
	rwr := transport.FromReadWriter(tpmDevice)
	tests := []struct {
		name    string
		alg     tpm2.TPMAlgID
		keySize int
	}{
		{"cfb_128", tpm2.TPMAlgCFB, 128},
		{"cfb_256", tpm2.TPMAlgCFB, 256},
		{"cbc_128", tpm2.TPMAlgCBC, 128},
		{"ctr_128", tpm2.TPMAlgCTR, 128},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {

			keySensitive := make([]byte, tc.keySize/8)
			_, err := rand.Read(keySensitive)
			require.NoError(t, err)

			k, err := NewImportKey(&NewImportConfig{
				TPMDevice:  tpmDevice,
				Alg:        "aes",
				RawKey:     keySensitive,
				AESAlg:     tc.alg,
				AESKeySize: tc.keySize,
				Parent:     tpm2.TPMRHOwner.HandleValue(),
			})
			require.NoError(t, err)

			regenKey, err := keyfile.Decode(k)
			require.NoError(t, err)

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

			aesKey, err := tpm2.Load{
				ParentHandle: tpm2.NamedHandle{
					Handle: primary.ObjectHandle,
					Name:   primary.Name,
				},
				InPublic:  regenKey.Pubkey,
				InPrivate: regenKey.Privkey,
			}.Execute(rwr)
			require.NoError(t, err)
			defer func() {
				flushContextCmd := tpm2.FlushContext{
					FlushHandle: aesKey.ObjectHandle,
				}
				_, _ = flushContextCmd.Execute(rwr)
			}()

			stringToEncrypt := "00000000fooooooo"

			data := []byte(stringToEncrypt)

			iv := make([]byte, aes.BlockSize)
			_, err = io.ReadFull(rand.Reader, iv)
			require.NoError(t, err)

			keyAuth := tpm2.AuthHandle{
				Handle: aesKey.ObjectHandle,
				Name:   aesKey.Name,
				Auth:   tpm2.PasswordAuth(nil),
			}

			encrypted, err := encryptDecryptSymmetric(rwr, keyAuth, iv, data, tc.alg, false)
			require.NoError(t, err)

			decrypted, err := encryptDecryptSymmetric(rwr, keyAuth, iv, encrypted, tc.alg, true)
			require.NoError(t, err)

			require.Equal(t, decrypted, data)
		})
	}

}

func TestImportHMAC(t *testing.T) {

	tpmDevice, err := net.Dial("tcp", swTPMPath)
	require.NoError(t, err)
	defer tpmDevice.Close()
	rwr := transport.FromReadWriter(tpmDevice)
	tests := []struct {
		name    string
		hsh     tpm2.TPMAlgID
		keySize int
	}{
		{"SHA256", tpm2.TPMAlgSHA256, 32},
		{"SHA512", tpm2.TPMAlgSHA256, 64},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {

			keySensitive := make([]byte, tc.keySize)
			_, err := rand.Read(keySensitive)
			require.NoError(t, err)

			k, err := NewImportKey(&NewImportConfig{
				TPMDevice: tpmDevice,
				Alg:       "hmac",
				RawKey:    keySensitive,
				HashAlg:   tc.hsh,
				Parent:    tpm2.TPMRHOwner.HandleValue(),
			})
			require.NoError(t, err)

			regenKey, err := keyfile.Decode(k)
			require.NoError(t, err)

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
			defer func() {
				flushContextCmd := tpm2.FlushContext{
					FlushHandle: hmacKey.ObjectHandle,
				}
				_, _ = flushContextCmd.Execute(rwr)
			}()

			stringToHash := "00000000fooooooo"

			data := []byte(stringToHash)
			objAuth := &tpm2.TPM2BAuth{
				Buffer: []byte(nil),
			}
			hmacBytes, err := thmac(rwr, data, hmacKey.ObjectHandle, hmacKey.Name, tpm2.PasswordAuth(nil), *objAuth)
			require.NoError(t, err)

			// run std hmac and compare

			//expectedMAC := "7c50506d993b4a10e5ae6b33ca951bf2b8c8ac399e0a34026bb0ac469bea3de2"
			tch, err := tc.hsh.Hash()
			require.NoError(t, err)

			hmacInstance := stdhmac.New(tch.New, keySensitive)
			_, err = hmacInstance.Write(data)
			require.NoError(t, err)

			expectedMAC := hmacInstance.Sum(nil)

			require.Equal(t, hmacBytes, expectedMAC)
		})
	}

}

func thmac(rwr transport.TPM, data []byte, objHandle tpm2.TPMHandle, objName tpm2.TPM2BName, or_sess tpm2.Session, objAuth tpm2.TPM2BAuth) ([]byte, error) {

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
			Auth:   or_sess, // sas,
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
