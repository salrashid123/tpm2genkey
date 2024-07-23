package tpm2genkey

import (
	"os"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/require"
)

var ()

func TestToPEMNoAuth(t *testing.T) {

	pu, err := os.ReadFile("./testdata/convert/nouserauth/key.pub")
	require.NoError(t, err)

	pr, err := os.ReadFile("./testdata/convert/nouserauth/key.prv")
	require.NoError(t, err)

	pemBytes, err := os.ReadFile("./testdata/convert/nouserauth/private.pem")
	require.NoError(t, err)

	p, err := ToPEM(&ToPEMConfig{
		Public:      pu,
		Private:     pr,
		Parent:      tpm2.TPMRHOwner.HandleValue(),
		Password:    []byte(""),
		Description: "",
		Debug:       false,
	})
	require.NoError(t, err)

	require.Equal(t, pemBytes, p)
}

func TestToPEMAuth(t *testing.T) {

	pu, err := os.ReadFile("./testdata/convert/userauth/key.pub")
	require.NoError(t, err)

	pr, err := os.ReadFile("./testdata/convert/userauth/key.prv")
	require.NoError(t, err)

	pemBytes, err := os.ReadFile("./testdata/convert/userauth/private.pem")
	require.NoError(t, err)

	p, err := ToPEM(&ToPEMConfig{
		Public:      pu,
		Private:     pr,
		Parent:      tpm2.TPMRHOwner.HandleValue(),
		Password:    []byte("foo"),
		Description: "",
		Debug:       false,
	})
	require.NoError(t, err)

	require.Equal(t, pemBytes, p)

}

func TestFromPEM(t *testing.T) {

	pub, err := os.ReadFile("./testdata/convert/nouserauth/key.pub")
	require.NoError(t, err)

	prb, err := os.ReadFile("./testdata/convert/nouserauth/key.prv")
	require.NoError(t, err)

	pemBytes, err := os.ReadFile("./testdata/convert/nouserauth/private.pem")
	require.NoError(t, err)

	_, pu, pr, err := FromPEM(&FromPEMConfig{
		PEM: pemBytes,
	})
	require.NoError(t, err)

	require.Equal(t, pu, pub)
	require.Equal(t, pr, prb)
}
