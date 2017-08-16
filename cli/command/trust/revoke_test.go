package trust

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/docker/cli/cli/internal/test"
	ctxu "github.com/docker/distribution/context"
	"github.com/docker/docker/pkg/testutil"
	"github.com/docker/notary"
	"github.com/docker/notary/client"
	"github.com/docker/notary/cryptoservice"
	"github.com/docker/notary/passphrase"
	"github.com/docker/notary/server"
	"github.com/docker/notary/server/storage"
	"github.com/docker/notary/trustmanager"
	"github.com/docker/notary/trustpinning"
	"github.com/docker/notary/tuf/data"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func fullTestServer(t *testing.T) *httptest.Server {
	var passphraseRetriever = passphrase.ConstantRetriever("password")
	// Set up server
	ctx := context.WithValue(
		context.Background(), notary.CtxKeyMetaStore, storage.NewMemStorage())

	// Do not pass one of the const KeyAlgorithms here as the value! Passing a
	// string is in itself good test that we are handling it correctly as we
	// will be receiving a string from the configuration.
	ctx = context.WithValue(ctx, notary.CtxKeyKeyAlgo, "ecdsa")

	// Eat the logs instead of spewing them out
	var b bytes.Buffer
	l := logrus.New()
	l.Out = &b
	ctx = ctxu.WithLogger(ctx, logrus.NewEntry(l))

	cryptoService := cryptoservice.NewCryptoService(trustmanager.NewKeyMemoryStore(passphraseRetriever))
	return httptest.NewServer(server.RootHandler(ctx, nil, *cryptoService, nil, nil, nil))
}

func TestTrustRevokeErrors(t *testing.T) {
	testCases := []struct {
		name          string
		args          []string
		expectedError string
	}{
		{
			name:          "not-enough-args",
			expectedError: "requires exactly 1 argument(s)",
		},
		{
			name:          "too-many-args",
			args:          []string{"remote1", "remote2"},
			expectedError: "requires exactly 1 argument",
		},
		{
			name:          "sha-reference",
			args:          []string{"870d292919d01a0af7e7f056271dc78792c05f55f49b9b9012b6d89725bd9abd"},
			expectedError: "invalid repository name",
		},
		{
			name:          "trust-data-for-tag-does-not-exist",
			args:          []string{"alpine:foo"},
			expectedError: "could not remove signature for alpine:foo: No trust data for foo",
		},
		{
			name:          "invalid-img-reference",
			args:          []string{"ALPINE"},
			expectedError: "invalid reference format",
		},
		{
			name: "unsigned-img-reference",
			args: []string{"riyaz/unsigned-img:v1"},
			expectedError: strings.Join([]string{
				"could not remove signature for riyaz/unsigned-img:v1:",
				"notary.docker.io does not have trust data for docker.io/riyaz/unsigned-img",
			}, " "),
		},
	}
	for _, tc := range testCases {
		buf := new(bytes.Buffer)
		cmd := newRevokeCommand(
			test.NewFakeCliWithOutput(&fakeClient{}, buf))
		cmd.SetArgs(tc.args)
		cmd.SetOutput(ioutil.Discard)
		testutil.ErrorContains(t, cmd.Execute(), tc.expectedError)
	}
}

func TestRevokeSingleSig(t *testing.T) {
	passwd := "abcd"

	ts := fullTestServer(t)
	defer ts.Close()

	tmpDir, err := ioutil.TempDir("", "notary-test-")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	notaryRepo, err := client.NewFileCachedNotaryRepository(tmpDir, "gun", ts.URL, nil, passphrase.ConstantRetriever(passwd), trustpinning.TrustPinConfig{})
	assert.NoError(t, err)

	// stage targets/user
	userRole := data.RoleName("targets/user")
	userKey := data.NewPublicKey("algoA", []byte("a"))

	notaryRepo.AddDelegation(userRole, []data.PublicKey{userKey}, []string{""})
	hashes := data.Hashes{}
	target := &client.Target{Name: "v1", Hashes: hashes, Length: 10}
	notaryRepo.AddTarget(target, userRole)
	notaryRepo.Publish()

	// add target

	//	addStagedSigner(notaryRepo, userRole, []data.PublicKey{userKey})

	//revoke that sig
	fmt.Println("Debug print:")
	fmt.Println(notaryRepo.ListTargets())
	//revokeSingleSig(notaryRepo, <tag>)

}
